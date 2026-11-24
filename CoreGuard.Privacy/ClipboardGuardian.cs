using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace CoreGuard.Privacy;

/// <summary>Type d'alerte émise par le gardien du presse-papiers. Jamais de contenu brut (zéro secret en log).</summary>
public enum ClipboardAlertKind { HijackRestored, CryptoAddressSwapped, SecretCleared }

public sealed record ClipboardAlert(ClipboardAlertKind Kind, string Detail, DateTime WhenUtc);

/// <summary>
/// Écoute le presse-papiers via AddClipboardFormatListener sur une fenêtre message-only cachée
/// (thread STA dédié). Restaure la valeur d'origine en cas de détournement et efface les secrets après un délai.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ClipboardGuardian : IDisposable
{
    private const int WM_CLIPBOARDUPDATE = 0x031D;
    private static readonly IntPtr HWND_MESSAGE = new(-3);

    [DllImport("user32.dll", SetLastError = true)] private static extern bool AddClipboardFormatListener(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern IntPtr GetClipboardOwner();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);

    private readonly TimeSpan _secretLifetime;
    private readonly object _gate = new();
    private Thread? _thread;
    private MessageWindow? _window;
    private string? _lastText;
    private DateTime _lastChangeUtc = DateTime.MinValue;
    private volatile bool _ignoreNext;
    private System.Threading.Timer? _clearTimer;

    public event EventHandler<ClipboardAlert>? AlertRaised;

    public ClipboardGuardian(TimeSpan? secretLifetime = null) => _secretLifetime = secretLifetime ?? TimeSpan.FromSeconds(30);

    public void Start()
    {
        if (_thread is not null) return;
        using var ready = new ManualResetEventSlim();
        _thread = new Thread(() =>
        {
            try
            {
                _window = new MessageWindow(this);
                ready.Set();
                Application.Run();
            }
            catch { ready.Set(); /* dégradation : pas de garde si la fenêtre échoue */ }
        }) { IsBackground = true, Name = "CoreGuard.Clipboard" };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
        ready.Wait(TimeSpan.FromSeconds(5));
    }

    public void Dispose()
    {
        _clearTimer?.Dispose();
        try { _window?.Invoke(() => { _window.Destroy(); Application.ExitThread(); }); } catch { }
        _window = null; _thread = null;
    }

    private void OnClipboardUpdate()
    {
        try
        {
            if (_ignoreNext) { _ignoreNext = false; return; }
            string? text = Clipboard.ContainsText() ? Clipboard.GetText() : null;
            var now = DateTime.UtcNow;
            string? previous; TimeSpan delta;
            lock (_gate) { previous = _lastText; delta = now - _lastChangeUtc; }

            if (previous is not null && text is not null && text != previous)
            {
                bool swap = ClipboardAnalysis.IsAddressSwap(previous, text);
                bool suspicious = ClipboardAnalysis.IsSuspiciousModification(delta, ForegroundOwnsClipboard());
                if (swap && delta < ClipboardAnalysis.SuspiciousDelay)
                {
                    Restore(previous);
                    Raise(ClipboardAlertKind.CryptoAddressSwapped, "Adresse crypto remplacée ; valeur d'origine restaurée.");
                    return;
                }
                if (suspicious)
                {
                    Restore(previous);
                    Raise(ClipboardAlertKind.HijackRestored, "Modification suspecte du presse-papiers ; valeur d'origine restaurée.");
                    return;
                }
            }

            lock (_gate) { _lastText = text; _lastChangeUtc = now; }
            if (ClipboardAnalysis.IsSecret(text)) ScheduleClear(text!);
        }
        catch { /* le presse-papiers peut être verrouillé par un autre processus */ }
    }

    private void Restore(string value)
    {
        _ignoreNext = true;
        try { Clipboard.SetText(value); } catch { _ignoreNext = false; }
    }

    private void ScheduleClear(string secret)
    {
        _clearTimer?.Dispose();
        _clearTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                // On ne vide que si le secret est toujours présent (l'utilisateur a pu copier autre chose).
                _window?.Invoke(() =>
                {
                    if (Clipboard.ContainsText() && Clipboard.GetText() == secret)
                    {
                        _ignoreNext = true;
                        Clipboard.Clear();
                        Raise(ClipboardAlertKind.SecretCleared, "Secret détecté dans le presse-papiers ; vidé automatiquement.");
                    }
                });
            }
            catch { }
        }, null, _secretLifetime, Timeout.InfiniteTimeSpan);
    }

    /// <summary>Vrai si le processus au premier plan est le détenteur du presse-papiers.</summary>
    private static bool ForegroundOwnsClipboard()
    {
        var fg = GetForegroundWindow();
        var owner = GetClipboardOwner();
        if (fg == IntPtr.Zero || owner == IntPtr.Zero) return false;
        GetWindowThreadProcessId(fg, out var fgPid);
        GetWindowThreadProcessId(owner, out var ownerPid);
        return fgPid != 0 && fgPid == ownerPid;
    }

    private void Raise(ClipboardAlertKind kind, string detail) =>
        AlertRaised?.Invoke(this, new ClipboardAlert(kind, detail, DateTime.UtcNow));

    /// <summary>Fenêtre message-only cachée recevant WM_CLIPBOARDUPDATE.</summary>
    private sealed class MessageWindow : NativeWindow
    {
        private readonly ClipboardGuardian _owner;
        private readonly SynchronizationContext _ctx;

        public MessageWindow(ClipboardGuardian owner)
        {
            _owner = owner;
            _ctx = new WindowsFormsSynchronizationContext();
            CreateHandle(new CreateParams { Parent = HWND_MESSAGE });
            AddClipboardFormatListener(Handle);
        }

        /// <summary>Exécute l'action sur le thread STA de la fenêtre.</summary>
        public void Invoke(Action a) => _ctx.Send(_ => a(), null);

        public void Destroy()
        {
            if (Handle != IntPtr.Zero) { RemoveClipboardFormatListener(Handle); DestroyHandle(); }
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_CLIPBOARDUPDATE) _owner.OnClipboardUpdate();
            base.WndProc(ref m);
        }
    }
}
