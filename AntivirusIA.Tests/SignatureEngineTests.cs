using AntivirusIA.Core.Models;
using AntivirusIA.Engines;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class SignatureEngineTests
{
    private const string HashDeAbc =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private static async Task<IReadOnlyList<Indicator>> AnalyserAsync(string contenuFichier)
    {
        string fichier = Path.GetTempFileName();
        string signatures = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(fichier, contenuFichier);
            await File.WriteAllTextAsync(signatures,
                $$"""{ "signatures": [ { "sha256": "{{HashDeAbc}}", "name": "Test-Signature" } ] }""");

            var moteur = new SignatureEngine(signatures);
            var rapport = new FileReport
            {
                FullPath = fichier,
                SizeBytes = new FileInfo(fichier).Length
            };
            return await moteur.AnalyzeAsync(rapport);
        }
        finally
        {
            File.Delete(fichier);
            File.Delete(signatures);
        }
    }

    [TestMethod]
    public async Task Fichier_au_hash_connu_est_detecte()
    {
        var indices = await AnalyserAsync("abc");

        Assert.AreEqual(1, indices.Count);
        Assert.AreEqual(100, indices[0].Points);
    }

    [TestMethod]
    public async Task Fichier_au_hash_inconnu_n_est_pas_detecte()
    {
        var indices = await AnalyserAsync("bonjour");

        Assert.AreEqual(0, indices.Count);
    }
}