using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CoreGuard.Devices;

/// <summary>
/// Blocage du clavier pendant le verrouillage d'urgence (hook WH_KEYBOARD_LL sur un thread dédié).
/// - Toujours bloqués : touches Windows, menu contextuel, Alt+Tab, Alt+Échap, Ctrl+Échap, Alt+F4.
/// - Si l'écran de verrouillage n'est pas au premier plan : TOUTES les frappes sont avalées.
/// Seule exception impossible à intercepter par un logiciel : Ctrl+Alt+Suppr (séquence sécurisée de Windows),
/// d'où le durcissement du processus pendant le verrouillage (le Gestionnaire des tâches ne peut pas le fermer).
/// </summary>
public sealed partial class InputLockHook : IDisposable
{
    private static InputLockHook? s_active;

    private readonly Func<IntPtr> _lockWindow;
    private Thread? _thread;
    private uint _threadId;
    private IntPtr _hook;

    /// <param name="lockWindow">Handle de la fenêtre de verrouillage (seule à recevoir des frappes).</param>
    public InputLockHook(Func<IntPtr> lockWindow) => _lockWindow = lockWindow;

    public bool Start()
    {
        if (Interlocked.CompareExchange(ref s_active, this, null) is not null) return false;
        using var ready = new ManualResetEventSlim();
        _thread = new Thread(() => Loop(ready)) { IsBackground = true, Name = "CoreGuard.InputLock" };
        _thread.Start();
        ready.Wait(TimeSpan.FromSeconds(5));
        if (_hook != IntPtr.Zero) return true;
        Interlocked.CompareExchange(ref s_active, null, this);
        return false;
    }

    private void Loop(ManualResetEventSlim ready)
    {
        _threadId = GetCurrentThreadId();
        unsafe
        {
            _hook = SetWindowsHookExW(13, (IntPtr)(delegate* unmanaged<int, IntPtr, IntPtr, IntPtr>)&Proc, GetModuleHandleW(null), 0);
        }
        ready.Set();
        if (_hook == IntPtr.Zero) return;
        while (GetMessageW(out Msg msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(in msg);
            DispatchMessageW(in msg);
        }
        UnhookWindowsHookEx(_hook);
        _hook = IntPtr.Zero;
    }

    /// <summary>Faut-il avaler cette touche ? (logique pure, testable)</summary>
    public static bool ShouldBlock(int vk, bool altDown, bool ctrlDown, bool lockWindowForeground)
    {
        if (!lockWindowForeground) return true;
        if (vk is VkLWin or VkRWin or VkApps) return true;
        if (altDown && vk is VkTab or VkEscape or VkF4) return true;
        if (ctrlDown && vk == VkEscape) return true;
        return false;
    }

    [UnmanagedCallersOnly]
    private static IntPtr Proc(int code, IntPtr wParam, IntPtr lParam)
    {
        try
        {
            var hook = s_active;
            if (code >= 0 && hook is not null)
            {
                var data = Marshal.PtrToStructure<KbdLlHookStruct>(lParam);
                bool alt = (data.Flags & LlkhfAltDown) != 0;
                bool ctrl = (GetAsyncKeyState(VkControl) & 0x8000) != 0;
                bool foreground = GetForegroundWindow() == hook._lockWindow();
                if (ShouldBlock((int)data.VkCode, alt, ctrl, foreground)) return 1;
            }
        }
        catch
        {
            // Jamais d'exception vers Windows
        }
        return CallNextHookEx(IntPtr.Zero, code, wParam, lParam);
    }

    public void Dispose()
    {
        if (_threadId != 0) PostThreadMessageW(_threadId, 0x0012 /* WM_QUIT */, IntPtr.Zero, IntPtr.Zero);
        _thread?.Join(TimeSpan.FromSeconds(2));
        Interlocked.CompareExchange(ref s_active, null, this);
    }

    /// <summary>Verrouille la session Windows (écran de connexion) : le voleur doit d'abord connaître le mot de passe Windows.</summary>
    public static bool LockWindowsSession() => LockWorkStation();

    // ---------- P/Invoke ----------

    private const int VkTab = 0x09, VkEscape = 0x1B, VkF4 = 0x73, VkLWin = 0x5B, VkRWin = 0x5C, VkApps = 0x5D, VkControl = 0x11;
    private const uint LlkhfAltDown = 0x20;

    [StructLayout(LayoutKind.Sequential)]
    private struct KbdLlHookStruct { public uint VkCode, ScanCode, Flags, Time; public IntPtr ExtraInfo; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Msg { public IntPtr Hwnd; public uint Message; public IntPtr WParam, LParam; public uint Time; public int PtX, PtY; }

    [LibraryImport("user32.dll", SetLastError = true)] private static partial IntPtr SetWindowsHookExW(int idHook, IntPtr proc, IntPtr module, uint threadId);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool UnhookWindowsHookEx(IntPtr hook);
    [LibraryImport("user32.dll")] private static partial IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr wParam, IntPtr lParam);
    [LibraryImport("user32.dll")] private static partial int GetMessageW(out Msg msg, IntPtr hwnd, uint min, uint max);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool TranslateMessage(in Msg msg);
    [LibraryImport("user32.dll")] private static partial IntPtr DispatchMessageW(in Msg msg);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool PostThreadMessageW(uint threadId, uint msg, IntPtr wParam, IntPtr lParam);
    [LibraryImport("user32.dll")] private static partial IntPtr GetForegroundWindow();
    [LibraryImport("user32.dll")] private static partial short GetAsyncKeyState(int vk);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool LockWorkStation();
    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial IntPtr GetModuleHandleW(string? name);
    [LibraryImport("kernel32.dll")] private static partial uint GetCurrentThreadId();
}
