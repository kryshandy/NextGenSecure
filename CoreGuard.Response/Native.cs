using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CoreGuard.Response;

internal static partial class Native
{
    public const int ProcessTerminate = 0x0001;
    public const int ProcessSuspendResume = 0x0800;
    public const int ProcessQueryLimitedInformation = 0x1000;
    public const int ReadControl = 0x00020000;
    public const int WriteDac = 0x00040000;
    public const int Synchronize = 0x00100000;
    public const int ProcessAllAccess = 0x001FFFFF;

    public const int ErrorAccessDenied = 5;
    public const uint ExitCodeTerminatedByCoreGuard = 0xC0DE0001;

    public const int SeKernelObject = 6;
    public const uint DaclSecurityInformation = 0x00000004;

    public static int LastError => Marshal.GetLastPInvokeError();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeProcessHandle OpenProcess(int access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool IsProcessCritical(SafeProcessHandle process, [MarshalAs(UnmanagedType.Bool)] out bool critical);

    [LibraryImport("ntdll.dll")]
    public static partial int NtSuspendProcess(SafeProcessHandle process);

    [LibraryImport("ntdll.dll")]
    public static partial int NtResumeProcess(SafeProcessHandle process);

    [LibraryImport("advapi32.dll")]
    public static partial uint SetSecurityInfo(SafeProcessHandle handle, int objectType, uint securityInfo,
        IntPtr owner, IntPtr group, byte[] dacl, IntPtr sacl);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, [Out] char[] buffer, ref uint size);

    /// <summary>Chemin complet de l'exécutable d'un processus (fonctionne aussi entre 32 et 64 bits).</summary>
    public static string? GetImagePath(int pid)
    {
        using var h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h.IsInvalid) return null;
        var buffer = new char[1024];
        uint size = (uint)buffer.Length;
        return QueryFullProcessImageName(h, 0, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
    }
}
