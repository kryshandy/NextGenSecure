using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CoreGuard.Devices;

/// <summary>
/// Moniteur BadUSB (Rubber Ducky, Digispark, câbles O.MG…) : un périphérique qui se présente comme un clavier et
/// tape des commandes à une vitesse surhumaine.
/// - Hook clavier bas niveau (WH_KEYBOARD_LL) sur un thread dédié : chaque appui passe par
///   <see cref="KeyboardInjectionGuard"/>, qui peut l'avaler (blocage de l'injection).
/// - Surveillance des claviers branchés (GetRawInputDeviceList, scrutation 2 s) : un nouveau clavier déclenche une
///   alerte et une période de vigilance (seuils abaissés).
/// Doit tourner dans la session de l'utilisateur (processus de l'UI) : un service en session 0 ne voit pas son clavier.
/// </summary>
public sealed partial class BadUsbMonitor : IDisposable
{
    private static readonly TimeSpan DevicePoll = TimeSpan.FromSeconds(2);

    private static BadUsbMonitor? s_active; // le callback du hook est statique (UnmanagedCallersOnly)

    private readonly KeyboardInjectionGuard _guard = new();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private Thread? _hookThread;
    private uint _hookThreadId;
    private IntPtr _hook;
    private Timer? _deviceTimer;
    private HashSet<IntPtr> _keyboards = [];

    public event EventHandler<InjectionAlert>? InjectionDetected;

    /// <summary>Nouveau clavier branché (nom système du périphérique HID).</summary>
    public event EventHandler<string>? KeyboardConnected;

    public bool IsRunning => _hook != IntPtr.Zero;

    /// <summary>Démarre le hook et la surveillance des claviers. Faux si le hook n'a pas pu être posé.</summary>
    public bool Start()
    {
        if (Interlocked.CompareExchange(ref s_active, this, null) is not null) return false; // un seul moniteur par processus

        _guard.InjectionDetected += (_, a) => ThreadPool.QueueUserWorkItem(_ =>
        {
            try { InjectionDetected?.Invoke(this, a); } catch { /* abonné fautif */ }
        });

        using var ready = new ManualResetEventSlim();
        _hookThread = new Thread(() => HookLoop(ready)) { IsBackground = true, Name = "CoreGuard.KeyboardHook" };
        _hookThread.Start();
        ready.Wait(TimeSpan.FromSeconds(5));

        if (_hook == IntPtr.Zero)
        {
            Interlocked.CompareExchange(ref s_active, null, this);
            return false;
        }

        _keyboards = ListKeyboards().Keys.ToHashSet();
        _deviceTimer = new Timer(_ => PollDevices(), null, DevicePoll, DevicePoll);
        return true;
    }

    private void HookLoop(ManualResetEventSlim ready)
    {
        _hookThreadId = GetCurrentThreadId();
        unsafe
        {
            _hook = SetWindowsHookExW(WhKeyboardLl, (IntPtr)(delegate* unmanaged<int, IntPtr, IntPtr, IntPtr>)&HookProc,
                GetModuleHandleW(null), 0);
        }
        ready.Set();
        if (_hook == IntPtr.Zero) return;

        // Boucle de messages : indispensable pour que Windows appelle le hook sur ce thread
        while (GetMessageW(out Msg msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(in msg);
            DispatchMessageW(in msg);
        }
        UnhookWindowsHookEx(_hook);
        _hook = IntPtr.Zero;
    }

    [UnmanagedCallersOnly]
    private static IntPtr HookProc(int code, IntPtr wParam, IntPtr lParam)
    {
        try
        {
            var monitor = s_active;
            if (code >= 0 && monitor is not null)
            {
                var data = Marshal.PtrToStructure<KbdLlHookStruct>(lParam);
                bool injected = (data.Flags & LlkhfInjected) != 0;
                double now = monitor._clock.Elapsed.TotalMilliseconds;
                int message = (int)wParam;
                bool swallow = message is WmKeyDown or WmSysKeyDown
                    ? monitor._guard.OnKeyDown((int)data.VkCode, injected, now)
                    : monitor._guard.OnKeyUp((int)data.VkCode, now);
                if (swallow) return 1; // frappe avalée : n'atteint aucune application
            }
        }
        catch
        {
            // Jamais d'exception vers Windows : la frappe passe
        }
        return CallNextHookEx(IntPtr.Zero, code, wParam, lParam);
    }

    private void PollDevices()
    {
        try
        {
            var current = ListKeyboards();
            foreach (var (handle, name) in current)
            {
                if (_keyboards.Contains(handle)) continue;
                _guard.EnterVigilance(_clock.Elapsed.TotalMilliseconds);
                try { KeyboardConnected?.Invoke(this, name); } catch { /* abonné fautif */ }
            }
            _keyboards = current.Keys.ToHashSet();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Liste des périphériques indisponible : nouvel essai au prochain tour
        }
    }

    /// <summary>Claviers HID présents : handle → nom système (ex. \\?\HID#VID_xxxx&amp;PID_yyyy…).</summary>
    internal static Dictionary<IntPtr, string> ListKeyboards()
    {
        var result = new Dictionary<IntPtr, string>();
        uint count = 0;
        uint size = (uint)Marshal.SizeOf<RawInputDeviceList>();
        if (GetRawInputDeviceList(null, ref count, size) == uint.MaxValue || count == 0) return result;

        var devices = new RawInputDeviceList[count];
        uint got = GetRawInputDeviceList(devices, ref count, size);
        if (got == uint.MaxValue) return result;

        for (int i = 0; i < got; i++)
        {
            if (devices[i].Type != RimTypeKeyboard) continue;
            result[devices[i].Device] = DeviceName(devices[i].Device) ?? "clavier";
        }
        return result;
    }

    private static unsafe string? DeviceName(IntPtr device)
    {
        uint chars = 0;
        GetRawInputDeviceInfoW(device, RidiDeviceName, null, ref chars);
        if (chars == 0 || chars > 1024) return null;
        var buffer = new char[chars];
        fixed (char* p = buffer)
        {
            return GetRawInputDeviceInfoW(device, RidiDeviceName, p, ref chars) is > 0 and not uint.MaxValue
                ? new string(buffer).TrimEnd('\0')
                : null;
        }
    }

    public void Dispose()
    {
        _deviceTimer?.Dispose();
        _deviceTimer = null;
        if (_hookThreadId != 0) PostThreadMessageW(_hookThreadId, WmQuit, IntPtr.Zero, IntPtr.Zero);
        _hookThread?.Join(TimeSpan.FromSeconds(2));
        Interlocked.CompareExchange(ref s_active, null, this);
    }

    // ---------- P/Invoke ----------

    private const int WhKeyboardLl = 13;
    private const int WmKeyDown = 0x0100, WmSysKeyDown = 0x0104;
    private const uint WmQuit = 0x0012;
    private const uint LlkhfInjected = 0x10;
    private const uint RimTypeKeyboard = 1;
    private const uint RidiDeviceName = 0x20000007;

    [StructLayout(LayoutKind.Sequential)]
    private struct KbdLlHookStruct
    {
        public uint VkCode, ScanCode, Flags, Time;
        public IntPtr ExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RawInputDeviceList
    {
        public IntPtr Device;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Msg
    {
        public IntPtr Hwnd;
        public uint Message;
        public IntPtr WParam, LParam;
        public uint Time;
        public int PtX, PtY;
    }

    [LibraryImport("user32.dll", SetLastError = true)]
    private static partial IntPtr SetWindowsHookExW(int idHook, IntPtr proc, IntPtr module, uint threadId);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool UnhookWindowsHookEx(IntPtr hook);

    [LibraryImport("user32.dll")]
    private static partial IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr wParam, IntPtr lParam);

    [LibraryImport("user32.dll")]
    private static partial int GetMessageW(out Msg msg, IntPtr hwnd, uint min, uint max);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TranslateMessage(in Msg msg);

    [LibraryImport("user32.dll")]
    private static partial IntPtr DispatchMessageW(in Msg msg);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool PostThreadMessageW(uint threadId, uint msg, IntPtr wParam, IntPtr lParam);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr GetModuleHandleW(string? name);

    [LibraryImport("kernel32.dll")]
    private static partial uint GetCurrentThreadId();

    [LibraryImport("user32.dll", SetLastError = true)]
    private static partial uint GetRawInputDeviceList([Out] RawInputDeviceList[]? devices, ref uint count, uint size);

    [LibraryImport("user32.dll", SetLastError = true)]
    private static unsafe partial uint GetRawInputDeviceInfoW(IntPtr device, uint command, char* data, ref uint size);
}
