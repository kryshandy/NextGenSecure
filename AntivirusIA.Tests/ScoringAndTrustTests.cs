using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;
using AntivirusIA.Core.Services;
using AntivirusIA.Engines;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class ScoringAndTrustTests
{
    private static ScanResult Result(FileTrust? trust, params Indicator[] indicators)
    {
        var r = new ScanResult { File = new FileReport { FullPath = @"C:\x.exe" }, Trust = trust };
        r.Indicators.AddRange(indicators);
        return r;
    }

    private static readonly FileTrust Signed = new(true, true, "Editeur");

    [TestMethod]
    public void Signature_valide_attenue_les_heuristiques()
    {
        var heur = new Indicator("PE", "imports", 35);
        var entropy = new Indicator("PE", "entropie", 20);
        var rwx = new Indicator("PE", "rwx", 15);

        Assert.AreEqual(70, Result(null, heur, entropy, rwx).Score);
        Assert.AreEqual(70 / ScanResult.TrustedHeuristicDivisor, Result(Signed, heur, entropy, rwx).Score);
    }

    [TestMethod]
    public void Signature_valide_n_attenue_jamais_un_indice_definitif()
    {
        var hash = new Indicator("Signatures", "hash connu", 100, Definitive: true);
        Assert.AreEqual(100, Result(Signed, hash).Score);
    }

    [TestMethod]
    public void Signature_invalide_n_attenue_rien()
    {
        var heur = new Indicator("PE", "imports", 40);
        Assert.AreEqual(40, Result(new FileTrust(true, false), heur).Score);
    }

    [TestMethod]
    public void Le_score_reste_borne()
    {
        Assert.AreEqual(100, Result(null, new Indicator("a", "a", 80), new Indicator("b", "b", 80)).Score);
        Assert.AreEqual(0, Result(null, new Indicator("a", "a", -50)).Score);
    }

    private sealed class FakeTrust(FileTrust trust) : IFileTrustProvider
    {
        public int Calls { get; private set; }
        public Task<FileTrust> EvaluateAsync(string path, CancellationToken ct = default) { Calls++; return Task.FromResult(trust); }
    }

    private sealed class FixedEngine(params Indicator[] indicators) : IDetectionEngine
    {
        public string Name => "Fixe";
        public Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<Indicator>>(indicators);
    }

    private sealed class CrashingEngine : IDetectionEngine
    {
        public string Name => "Plantage";
        public Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default) =>
            throw new InvalidOperationException("boum");
    }

    private static async Task<ScanResult> ScanAsync(IFileTrustProvider? trust, params IDetectionEngine[] engines)
    {
        string path = Path.GetTempFileName();
        try
        {
            return await new ScanPipeline(engines, new ScoringService(), trust).ScanFileAsync(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task Le_pipeline_applique_la_signature_numerique()
    {
        var trust = new FakeTrust(Signed);
        var r = await ScanAsync(trust, new FixedEngine(new Indicator("PE", "heuristique", 80)));

        Assert.AreEqual(1, trust.Calls);
        Assert.AreEqual(Verdict.Sain, r.Verdict);
        Assert.AreEqual(20, r.Score);
    }

    [TestMethod]
    public async Task Le_pipeline_ne_verifie_pas_la_signature_sans_heuristique()
    {
        var trust = new FakeTrust(Signed);
        await ScanAsync(trust, new FixedEngine());
        Assert.AreEqual(0, trust.Calls);
    }

    [TestMethod]
    public async Task Un_moteur_qui_plante_rend_l_analyse_incomplete_et_ajoute_des_points()
    {
        var r = await ScanAsync(null, new CrashingEngine(), new FixedEngine(new Indicator("X", "x", 20)));

        Assert.IsTrue(r.Incomplete);
        Assert.AreEqual(1, r.Warnings.Count);
        Assert.AreEqual(20 + ScanPipeline.EngineFailurePoints, r.Score);
        Assert.AreEqual(Verdict.Suspect, r.Verdict);
    }

    [TestMethod]
    public async Task Authenticode_fichier_non_signe()
    {
        string path = Path.GetTempFileName();
        try
        {
            var trust = await new AuthenticodeVerifier().EvaluateAsync(path);
            Assert.IsFalse(trust.IsTrusted);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task Authenticode_binaire_Microsoft_signe()
    {
        if (!OperatingSystem.IsWindows()) Assert.Inconclusive("Windows uniquement");

        // System.Private.CoreLib.dll porte une signature Authenticode intégrée (certificat Microsoft « .NET »)
        var trust = await new AuthenticodeVerifier().EvaluateAsync(typeof(object).Assembly.Location);
        Assert.IsTrue(trust.IsTrusted, "CoreLib devrait être signé");
        Assert.IsFalse(string.IsNullOrWhiteSpace(trust.Publisher), "l'éditeur doit être extrait du certificat");
    }

    [TestMethod]
    public async Task L_entropie_globale_n_est_plus_comptee_pour_un_PE()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
        var content = System.Security.Cryptography.RandomNumberGenerator.GetBytes(65536);
        content[0] = (byte)'M'; content[1] = (byte)'Z';
        await File.WriteAllBytesAsync(path, content);
        try
        {
            var report = new FileReport { FullPath = path, SizeBytes = content.Length };
            Assert.AreEqual(0, (await new EntropyAnalyzer().AnalyzeAsync(report)).Count);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
