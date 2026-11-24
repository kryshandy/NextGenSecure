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

    [TestMethod]
    public async Task Les_listes_texte_et_les_dossiers_sont_charges()
    {
        string dossier = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dossier);
        try
        {
            const string hashAbc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            await File.WriteAllTextAsync(Path.Combine(dossier, "flux.txt"),
                "# export de flux public\n" +
                hashAbc.ToUpperInvariant() + " Trojan.Test\n" +
                "ligne-invalide\n" +
                new string('a', 64) + ",\"Autre\"\n");
            await File.WriteAllTextAsync(Path.Combine(dossier, "ignore.md"), new string('b', 64));

            var moteur = new SignatureEngine([dossier, Path.Combine(dossier, "absent")]);
            Assert.AreEqual(2, moteur.Count);

            string fichier = Path.Combine(dossier, "abc.dat");
            await File.WriteAllTextAsync(fichier, "abc");
            var indices = await moteur.AnalyzeAsync(new FileReport { FullPath = fichier, SizeBytes = 3 });
            var hit = indices.Single();
            StringAssert.Contains(hit.Description, "Trojan.Test");
            Assert.IsTrue(hit.Definitive);
        }
        finally
        {
            Directory.Delete(dossier, true);
        }
    }
}
