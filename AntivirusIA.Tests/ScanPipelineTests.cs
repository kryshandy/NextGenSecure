using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;
using AntivirusIA.Core.Services;
using AntivirusIA.Engines;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class ScanPipelineTests
{
    private const string HashDeAbc =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private static async Task<ScanResult> ScannerAsync(string nomFichier, string contenu)
    {
        string dossier = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dossier);
        string fichier = Path.Combine(dossier, nomFichier);
        string signatures = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(fichier, contenu);
            await File.WriteAllTextAsync(signatures,
                $$"""{ "signatures": [ { "sha256": "{{HashDeAbc}}", "name": "Test-Signature" } ] }""");

            var pipeline = new ScanPipeline(
                new IDetectionEngine[]
                {
                    new SignatureEngine(signatures),
                    new EntropyAnalyzer(),
                    new HeuristicEngine()
                },
                new ScoringService());

            return await pipeline.ScanFileAsync(fichier);
        }
        finally
        {
            Directory.Delete(dossier, true);
            File.Delete(signatures);
        }
    }

    [TestMethod]
    public async Task Fichier_au_hash_connu_est_malveillant()
    {
        var resultat = await ScannerAsync("rapport.txt", "abc");

        Assert.AreEqual(Verdict.Malveillant, resultat.Verdict);
        Assert.AreEqual(100, resultat.Score);
    }

    [TestMethod]
    public async Task Fichier_banal_est_sain()
    {
        var resultat = await ScannerAsync("notes.txt", "bonjour");

        Assert.AreEqual(Verdict.Sain, resultat.Verdict);
        Assert.AreEqual(0, resultat.Score);
    }

    [TestMethod]
    public async Task Programme_deguise_en_document_est_suspect()
    {
        var resultat = await ScannerAsync("facture.pdf.exe", "bonjour");

        Assert.AreEqual(Verdict.Suspect, resultat.Verdict);
    }
}