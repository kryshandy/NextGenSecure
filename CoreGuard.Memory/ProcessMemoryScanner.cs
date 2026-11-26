using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CoreGuard.Memory;

/// <summary>Résultat du scan d'un processus.</summary>
public sealed record ProcessMemoryReport(int Pid, string ProcessName, IReadOnlyList<MemoryFinding> Findings);

/// <summary>Bilan d'un scan complet.</summary>
public sealed record MemoryScanSummary(int ProcessesScanned, int ProcessesSkipped, long RegionsExamined, IReadOnlyList<ProcessMemoryReport> Suspicious);

/// <summary>
/// Scan de la mémoire des processus (détection « fileless ») : VirtualQueryEx parcourt l'espace d'adressage,
/// ReadProcessMemory lit le début de chaque région privée exécutable, <see cref="MemoryRegionClassifier"/> décide.
/// Lecture seule : aucun processus n'est modifié ici (la réponse est décidée par l'appelant).
/// Les processus protégés (PPL : antivirus, lsass protégé…) ne peuvent pas être ouverts et sont ignorés.
/// </summary>
public static partial class ProcessMemoryScanner
{
    private const int HeadBytes = 0x1000;
    private const int MaxRegionsPerProcess = 200_000;
    private const int MaxFindingsPerProcess = 32;

    // Moteurs à compilation à la volée : leurs régions RWX sont normales (le PE en mémoire privée reste signalé)
    private static readonly HashSet<string> JitHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "java", "javaw", "chrome", "msedge", "msedgewebview2", "firefox", "brave", "opera", "node", "electron",
        "code", "Teams", "ms-teams", "Discord", "slack", "Spotify", "dotnet", "powershell", "pwsh", "devenv",
        "rider64", "idea64", "WindowsTerminal", "SearchHost", "StartMenuExperienceHost"
    };

    public static bool IsJitHost(string processName) => JitHosts.Contains(processName);

    /// <summary>Scanne un processus. Null s'il ne peut pas être ouvert (protégé, terminé, droits).</summary>
    public static ProcessMemoryReport? ScanProcess(int pid, CancellationToken ct = default) => ScanProcess(pid, ct, out _);

    internal static ProcessMemoryReport? ScanProcess(int pid, CancellationToken ct, out long regionsExamined)
    {
        regionsExamined = 0;
        string name;
        try { using var p = Process.GetProcessById(pid); name = p.ProcessName; }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { return null; }

        using SafeProcessHandle h = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, pid);
        if (h.IsInvalid) return null;

        var findings = new List<MemoryFinding>();
        byte[] head = new byte[HeadBytes];
        ulong address = 0;
        int count = 0;
        int mbiSize = Marshal.SizeOf<MemoryBasicInformation>();

        while (count++ < MaxRegionsPerProcess && findings.Count < MaxFindingsPerProcess)
        {
            ct.ThrowIfCancellationRequested();
            if (VirtualQueryEx(h, (IntPtr)(long)address, out MemoryBasicInformation mbi, (nuint)mbiSize) == 0) break;

            var region = new RegionInfo((ulong)(long)mbi.BaseAddress, (ulong)mbi.RegionSize, mbi.State, mbi.Type, mbi.Protect);
            regionsExamined++;

            if (MemoryRegionClassifier.IsCandidate(region))
            {
                int toRead = (int)Math.Min((ulong)HeadBytes, region.Size);
                if (ReadProcessMemory(h, mbi.BaseAddress, head, (nuint)toRead, out nuint read) && read >= 0x40)
                {
                    var finding = MemoryRegionClassifier.Classify(region, head.AsSpan(0, (int)read));
                    if (finding is not null) findings.Add(finding);
                }
            }

            ulong next = region.BaseAddress + region.Size;
            if (next <= address) break; // fin de l'espace d'adressage
            address = next;
        }

        return new ProcessMemoryReport(pid, name, findings);
    }

    /// <summary>Scanne tous les processus accessibles, sauf ceux exclus (CoreGuard lui-même…).</summary>
    public static MemoryScanSummary ScanAll(ISet<int> excludedPids, CancellationToken ct = default)
    {
        int scanned = 0, skipped = 0;
        long regions = 0;
        var suspicious = new List<ProcessMemoryReport>();

        foreach (var process in Process.GetProcesses())
        {
            int pid;
            using (process) pid = process.Id;
            ct.ThrowIfCancellationRequested();
            if (pid <= 4 || excludedPids.Contains(pid)) { skipped++; continue; }

            ProcessMemoryReport? report;
            try { report = ScanProcess(pid, ct, out long r); regions += r; }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is not OutOfMemoryException) { report = null; }

            if (report is null) { skipped++; continue; }
            scanned++;
            if (report.Findings.Count > 0) suspicious.Add(report);
        }
        return new MemoryScanSummary(scanned, skipped, regions, suspicious);
    }

    // ---------- P/Invoke ----------

    private const int ProcessQueryInformation = 0x0400;
    private const int ProcessVmRead = 0x0010;

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(int access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nuint VirtualQueryEx(SafeProcessHandle process, IntPtr address, out MemoryBasicInformation buffer, nuint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReadProcessMemory(SafeProcessHandle process, IntPtr baseAddress, [Out] byte[] buffer, nuint size, out nuint read);
}
