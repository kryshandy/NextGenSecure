using System.Runtime.InteropServices;
using System.Text;
using CoreGuard.Memory;
using static CoreGuard.Memory.MemoryRegionClassifier;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace CoreGuard.Memory.Tests;

[TestClass]
public sealed class MemoryScanTests
{
    private static byte[] FakePe()
    {
        var b = new byte[0x200];
        b[0] = (byte)'M'; b[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(b, 0x3C);
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(b, 0x80);
        return b;
    }

    private static RegionInfo Private(uint protect) => new(0x10000, 0x10000, MemCommit, MemPrivate, protect);

    // ---------- Classement (logique pure) ----------

    [TestMethod]
    public void Une_image_PE_en_memoire_privee_executable_est_signalee()
    {
        var f = Classify(Private(PageExecuteRead), FakePe());
        Assert.AreEqual(MemoryFindingKind.PeInPrivateMemory, f!.Kind);
    }

    [TestMethod]
    public void Une_region_RWX_sans_PE_est_un_signal_faible()
    {
        Assert.AreEqual(MemoryFindingKind.PrivateRwx, Classify(Private(PageExecuteReadWrite), new byte[0x200])!.Kind);
    }

    [TestMethod]
    public void Une_region_executable_en_lecture_seule_sans_PE_est_ignoree()
    {
        Assert.IsNull(Classify(Private(PageExecuteRead), new byte[0x200])); // code JIT finalisé (W^X)
    }

    [TestMethod]
    public void Les_vraies_DLL_chargees_par_Windows_sont_ignorees()
    {
        var image = new RegionInfo(0x10000, 0x10000, MemCommit, MemImage, PageExecuteRead);
        Assert.IsNull(Classify(image, FakePe()));
    }

    [TestMethod]
    public void Une_region_non_executable_est_ignoree()
    {
        Assert.IsNull(Classify(Private(0x04 /* PAGE_READWRITE */), FakePe()));
    }

    [TestMethod]
    [DataRow(0x3C)]   // e_lfanew trop petit
    [DataRow(0x1FE)]  // hors des octets lus
    [DataRow(0x81)]   // non aligné
    public void Un_en_tete_MZ_incoherent_n_est_pas_une_image_PE(int lfanew)
    {
        var b = FakePe();
        BitConverter.GetBytes(lfanew).CopyTo(b, 0x3C);
        Assert.IsFalse(LooksLikePe(b));
    }

    [TestMethod]
    public void Les_moteurs_JIT_connus_sont_reconnus()
    {
        Assert.IsTrue(ProcessMemoryScanner.IsJitHost("chrome"));
        Assert.IsTrue(ProcessMemoryScanner.IsJitHost("JAVA"));
        Assert.IsFalse(ProcessMemoryScanner.IsJitHost("notepad"));
    }

    // ---------- Scan réel du processus de test ----------

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, nuint size, uint type, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFree(IntPtr address, nuint size, uint type);

    private static IntPtr Plant(uint protect, byte[] content)
    {
        IntPtr p = VirtualAlloc(IntPtr.Zero, 0x10000, 0x3000, 0x04 /* RW pour écrire */);
        Assert.AreNotEqual(IntPtr.Zero, p);
        Marshal.Copy(content, 0, p, content.Length);
        Assert.IsTrue(VirtualProtect(p, 0x10000, protect, out _));
        return p;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr address, nuint size, uint newProtect, out uint oldProtect);

    [TestMethod]
    public void Le_scan_reel_trouve_un_faux_module_injecte_dans_ce_processus()
    {
        IntPtr zone = Plant(PageExecuteReadWrite, FakePe());
        try
        {
            var report = ProcessMemoryScanner.ScanProcess(Environment.ProcessId);
            Assert.IsNotNull(report);
            Assert.IsTrue(report.Findings.Any(f => f.Kind == MemoryFindingKind.PeInPrivateMemory && f.BaseAddress == (ulong)(long)zone),
                $"zone 0x{zone:X} attendue parmi : {string.Join(", ", report.Findings.Select(f => $"{f.Kind}@0x{f.BaseAddress:X}"))}");
        }
        finally
        {
            VirtualFree(zone, 0, 0x8000);
        }
    }

    [TestMethod]
    public void Le_scan_reel_ignore_un_faux_module_non_executable()
    {
        IntPtr zone = Plant(0x02 /* PAGE_READONLY */, FakePe());
        try
        {
            var report = ProcessMemoryScanner.ScanProcess(Environment.ProcessId);
            Assert.IsFalse(report!.Findings.Any(f => f.BaseAddress == (ulong)(long)zone));
        }
        finally
        {
            VirtualFree(zone, 0, 0x8000);
        }
    }

    [TestMethod]
    public void Le_scan_complet_parcourt_les_processus_sans_erreur()
    {
        var summary = ProcessMemoryScanner.ScanAll(new HashSet<int> { Environment.ProcessId });
        Assert.IsGreaterThan(0, summary.ProcessesScanned);
        Assert.IsGreaterThan(0L, summary.RegionsExamined);
    }

    [TestMethod]
    public void Un_processus_inexistant_renvoie_null()
    {
        Assert.IsNull(ProcessMemoryScanner.ScanProcess(int.MaxValue - 7));
    }
}
