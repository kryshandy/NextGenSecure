using System.Runtime.InteropServices;
using System.Text;

namespace CoreGuard.Behavior;

/// <summary>Scanner AMSI (amsi.dll). Dégrade proprement (renvoie false) si AMSI est indisponible.</summary>
public sealed class AmsiScanner : IDisposable
{
    private const int MaxScriptChars = 1_000_000;
    // AMSI_RESULT_DETECTED : tout résultat >= 32768 est considéré malveillant.
    private const int AmsiResultDetected = 32768;
    // 16384..32767 : bloqué par politique administrateur.
    private const int AmsiResultBlockedByAdmin = 16384;

    private readonly object _lock = new();
    private IntPtr _context;
    private bool _initialized;
    private bool _unavailable;
    private bool _disposed;

    /// <summary>Vrai si amsi.dll a pu être initialisée.</summary>
    public bool IsAvailable
    {
        get { lock (_lock) { EnsureInitialized(); return _initialized; } }
    }

    /// <summary>Scanne un script ; false si propre OU si AMSI est indisponible.</summary>
    public Task<bool> IsMaliciousAsync(string script) => Task.Run(() => IsMalicious(script));

    private bool IsMalicious(string? script)
    {
        if (string.IsNullOrEmpty(script)) return false;
        if (script.Length > MaxScriptChars) script = script[..MaxScriptChars];

        lock (_lock)
        {
            if (_disposed) return false;
            EnsureInitialized();
            if (!_initialized) return false;
            try
            {
                byte[] buffer = Encoding.Unicode.GetBytes(script);
                int hr = AmsiScanBuffer(_context, buffer, (uint)buffer.Length, "CoreGuard-script", IntPtr.Zero, out int result);
                if (hr != 0) return false;
                return result >= AmsiResultBlockedByAdmin;
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException)
            {
                _unavailable = true;
                return false;
            }
        }
    }

    private void EnsureInitialized()
    {
        if (_initialized || _unavailable || _disposed) return;
        try
        {
            int hr = AmsiInitialize("CoreGuard", out _context);
            if (hr == 0 && _context != IntPtr.Zero) _initialized = true;
            else _unavailable = true;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException)
        {
            _unavailable = true;
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            if (_initialized)
            {
                try { AmsiUninitialize(_context); } catch { /* best-effort */ }
                _initialized = false;
                _context = IntPtr.Zero;
            }
        }
    }

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr amsiContext);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length,
        string contentName, IntPtr amsiSession, out int result);
}
