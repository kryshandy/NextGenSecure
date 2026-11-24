using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using AntivirusIA.Core.Models;
using AntivirusIA.Engines;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class PeStaticEngineTests
{
    private const uint Code = 0x60000020;        // CODE | EXECUTE | READ
    private const uint CodeRwx = 0xE0000020;     // CODE | EXECUTE | READ | WRITE
    private const uint DonneesLecture = 0x40000040;

    private sealed record SectionSpec(string Nom, uint Caracteristiques, byte[] Contenu, uint? TailleVirtuelle = null);

    // Construit un PE32 minimal en mémoire : en-tête DOS, en-têtes PE, sections et table d'imports facultative
    private static byte[] ConstruirePe(List<SectionSpec> sections, string[]? imports)
    {
        var liste = new List<SectionSpec>(sections);
        byte[]? idata = null;
        uint rvaIdata = 0;
        if (imports is not null)
        {
            rvaIdata = 0x200000;
            idata = ConstruireIdata(imports, rvaIdata);
            liste.Add(new SectionSpec(".idata", DonneesLecture, idata));
        }

        const int tailleEntetes = 0x200;
        var fichier = new List<byte>(new byte[tailleEntetes]);
        var tampon = fichier.ToArray();

        static void E16(byte[] b, int o, int v) => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(o), (ushort)v);
        static void E32(byte[] b, int o, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o), v);

        tampon[0] = (byte)'M'; tampon[1] = (byte)'Z';
        E32(tampon, 0x3C, 0x40);
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(tampon, 0x40);

        int coff = 0x44;
        E16(tampon, coff, 0x14C);
        E16(tampon, coff + 2, liste.Count);
        E16(tampon, coff + 16, 224);
        E16(tampon, coff + 18, 0x0102);

        int opt = coff + 20;
        E16(tampon, opt, 0x10B);
        E32(tampon, opt + 16, 0x1000);
        E32(tampon, opt + 28, 0x400000);
        E32(tampon, opt + 32, 0x1000);
        E32(tampon, opt + 36, 0x200);
        E16(tampon, opt + 40, 4);
        E16(tampon, opt + 48, 4);
        E32(tampon, opt + 56, 0x201000);
        E32(tampon, opt + 60, tailleEntetes);
        E16(tampon, opt + 68, 3);
        E32(tampon, opt + 92, 16);
        if (imports is not null)
        {
            E32(tampon, opt + 96 + 8, rvaIdata);
            E32(tampon, opt + 96 + 12, (uint)idata!.Length);
        }

        int enteteSection = opt + 224;
        uint offsetFichier = tailleEntetes;
        var donnees = new List<byte>();
        for (int i = 0; i < liste.Count; i++)
        {
            var s = liste[i];
            uint brute = (uint)((s.Contenu.Length + 0x1FF) & ~0x1FF);
            int h = enteteSection + i * 40;
            Encoding.ASCII.GetBytes(s.Nom).CopyTo(tampon, h);
            E32(tampon, h + 8, s.TailleVirtuelle ?? (uint)s.Contenu.Length);
            E32(tampon, h + 12, s.Nom == ".idata" ? rvaIdata : 0x4000u * (uint)(i + 1));
            E32(tampon, h + 16, brute);
            E32(tampon, h + 20, offsetFichier);
            E32(tampon, h + 36, s.Caracteristiques);

            var bloc = new byte[brute];
            s.Contenu.CopyTo(bloc, 0);
            donnees.AddRange(bloc);
            offsetFichier += brute;
        }

        return [.. tampon, .. donnees];
    }

    // Table d'imports d'une seule DLL (kernel32.dll) avec les fonctions demandées
    private static byte[] ConstruireIdata(string[] fonctions, uint rva)
    {
        int tailleThunks = (fonctions.Length + 1) * 4;
        int debutIlt = 40;
        int debutNoms = debutIlt + tailleThunks;
        int offsetNoms = debutNoms;
        var noms = new List<byte>();
        var rvaNoms = new List<uint>();
        foreach (string f in fonctions)
        {
            rvaNoms.Add(rva + (uint)offsetNoms);
            var entree = new List<byte> { 0, 0 };
            entree.AddRange(Encoding.ASCII.GetBytes(f));
            entree.Add(0);
            if (entree.Count % 2 != 0) entree.Add(0);
            noms.AddRange(entree);
            offsetNoms += entree.Count;
        }
        uint rvaNomDll = rva + (uint)offsetNoms;
        var nomDll = Encoding.ASCII.GetBytes("kernel32.dll\0");

        var resultat = new byte[offsetNoms + nomDll.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(resultat.AsSpan(0), rva + (uint)debutIlt);  // OriginalFirstThunk
        BinaryPrimitives.WriteUInt32LittleEndian(resultat.AsSpan(12), rvaNomDll);             // Name
        BinaryPrimitives.WriteUInt32LittleEndian(resultat.AsSpan(16), rva + (uint)debutIlt);  // FirstThunk
        for (int i = 0; i < fonctions.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(resultat.AsSpan(debutIlt + i * 4), rvaNoms[i]);
        noms.CopyTo(resultat, debutNoms);
        nomDll.CopyTo(resultat, offsetNoms);
        return resultat;
    }

    private static byte[] CodeNormal() => Enumerable.Range(0, 4096).Select(i => (byte)(i % 7)).ToArray();

    // Analyse en mémoire (évite d'écrire sur disque un faux PE que l'antivirus de la machine pourrait bloquer)
    private static Task<IReadOnlyList<Indicator>> Analyser(byte[] contenu)
    {
        using var flux = new MemoryStream(contenu);
        return Task.FromResult(new PeStaticEngine().AnalyzeStream(flux));
    }

    [TestMethod]
    public async Task Fichier_non_PE_est_ignore()
    {
        var indices = await Analyser(Encoding.ASCII.GetBytes(new string('a', 4096)));
        Assert.AreEqual(0, indices.Count);
    }

    [TestMethod]
    public async Task Fichier_MZ_corrompu_est_signale_sans_exception()
    {
        var corrompu = new byte[512];
        corrompu[0] = (byte)'M'; corrompu[1] = (byte)'Z';
        RandomNumberGenerator.Fill(corrompu.AsSpan(2));

        // Échec sécurisé : un PE impossible à analyser n'est pas déclaré sain
        var indices = await Analyser(corrompu);
        Assert.AreEqual(1, indices.Count);
        Assert.AreEqual(PeStaticEngine.PointsPeMalforme, indices[0].Points);
    }

    [TestMethod]
    public async Task Pe_tronque_est_signale_sans_exception()
    {
        var pe = ConstruirePe([new(".text", Code, CodeNormal())], ["ExitProcess"]);
        var indices = await Analyser(pe[..0x150]);
        Assert.IsTrue(indices.All(i => i.Points == PeStaticEngine.PointsPeMalforme || i.Description.Contains("imports")));
        Assert.IsTrue(indices.Count >= 1, "un PE tronqué doit être signalé");
    }

    [TestMethod]
    public async Task Fichier_inexistant_renvoie_une_liste_vide()
    {
        var rapport = new FileReport { FullPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe"), SizeBytes = 4096 };
        var indices = await new PeStaticEngine().AnalyzeAsync(rapport);
        Assert.AreEqual(0, indices.Count);
    }

    [TestMethod]
    public async Task Pe_benin_n_est_pas_signale()
    {
        var pe = ConstruirePe([new(".text", Code, CodeNormal())], ["ExitProcess", "GetStdHandle"]);
        var indices = await Analyser(pe);
        Assert.AreEqual(0, indices.Count);
    }

    [TestMethod]
    public async Task Section_RWX_est_signalee()
    {
        var pe = ConstruirePe([new(".text", CodeRwx, CodeNormal())], ["ExitProcess"]);
        var indices = await Analyser(pe);

        Assert.IsTrue(indices.Any(i => i.Description.Contains("RWX") && i.Points == 15));
    }

    [TestMethod]
    public async Task Section_executable_tres_entropique_est_signalee()
    {
        var pe = ConstruirePe([new(".zone", Code, Enumerable.Range(0, 8192).Select(i => (byte)(i * 167 + i / 256)).ToArray())], ["ExitProcess"]);
        var indices = await Analyser(pe);

        Assert.IsTrue(indices.Any(i => i.Description.Contains("entropie") && i.Points == 20));
    }

    [TestMethod]
    public async Task Donnees_aleatoires_non_executables_ne_sont_pas_signalees()
    {
        var pe = ConstruirePe(
            [new(".text", Code, CodeNormal()), new(".rsrc", DonneesLecture, RandomNumberGenerator.GetBytes(8192))],
            ["ExitProcess"]);
        var indices = await Analyser(pe);

        Assert.AreEqual(0, indices.Count);
    }

    [TestMethod]
    public async Task Imports_sensibles_sont_signales()
    {
        var pe = ConstruirePe(
            [new(".text", Code, CodeNormal())],
            ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ExitProcess"]);
        var indices = await Analyser(pe);

        var indice = indices.Single(i => i.Description.StartsWith("Imports sensibles"));
        StringAssert.Contains(indice.Description, "WriteProcessMemory");
        StringAssert.Contains(indice.Description, "CreateRemoteThread");
        Assert.IsFalse(indice.Description.Contains("ExitProcess"));
        Assert.AreEqual(30, indice.Points);
    }

    [TestMethod]
    public async Task Absence_totale_d_imports_est_signalee()
    {
        var pe = ConstruirePe([new(".text", Code, CodeNormal())], null);
        var indices = await Analyser(pe);

        Assert.IsTrue(indices.Any(i => i.Description.Contains("Aucun import")));
    }

    [TestMethod]
    public async Task Desequilibre_taille_virtuelle_brute_est_signale()
    {
        var pe = ConstruirePe([new(".text", Code, CodeNormal(), TailleVirtuelle: 0x100000)], ["ExitProcess"]);
        var indices = await Analyser(pe);

        Assert.IsTrue(indices.Any(i => i.Description.Contains("taille virtuelle") && i.Points == 10));
    }

    [TestMethod]
    public async Task Fichier_verrouille_remonte_une_erreur_d_acces()
    {
        string chemin = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
        await File.WriteAllBytesAsync(chemin, ConstruirePe([new(".text", Code, CodeNormal())], ["ExitProcess"]));
        try
        {
            using var verrou = new FileStream(chemin, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            var rapport = new FileReport { FullPath = chemin, SizeBytes = new FileInfo(chemin).Length };
            await Assert.ThrowsExactlyAsync<IOException>(() => new PeStaticEngine().AnalyzeAsync(rapport));
        }
        finally
        {
            File.Delete(chemin);
        }
    }

    [TestMethod]
    public async Task Un_vrai_binaire_gere_est_analyse_sans_exception()
    {
        string chemin = typeof(PeStaticEngine).Assembly.Location;
        var rapport = new FileReport { FullPath = chemin, SizeBytes = new FileInfo(chemin).Length };

        var indices = await new PeStaticEngine().AnalyzeAsync(rapport);

        Assert.IsNotNull(indices);
        Assert.AreEqual("PE statique", new PeStaticEngine().Name);
    }
}
