using AntivirusIA.Core.Models;
using AntivirusIA.Infrastructure;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class SqliteScanRepositoryTests
{
    private static string NouveauDossier()
    {
        string dossier = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dossier);
        return dossier;
    }

    private static ScanResult NouveauResultat(string chemin, string sha, int points, Verdict verdict)
    {
        var rapport = new FileReport { FullPath = chemin, SizeBytes = 10, Sha256 = sha };
        var resultat = new ScanResult { File = rapport, Verdict = verdict };
        if (points > 0)
            resultat.Indicators.Add(new Indicator("Test", "indice de test", points));
        return resultat;
    }

    [TestMethod]
    public async Task Une_analyse_enregistree_apparait_dans_l_historique()
    {
        string racine = NouveauDossier();
        try
        {
            var depot = new SqliteScanRepository(Path.Combine(racine, "antivirus.db"));
            await depot.SaveScanAsync(NouveauResultat(@"C:\test\a.exe", "aaa", 40, Verdict.Suspect));

            var historique = await depot.GetHistoryAsync();

            Assert.AreEqual(1, historique.Count);
            Assert.AreEqual(@"C:\test\a.exe", historique[0].Path);
            Assert.AreEqual(40, historique[0].Score);
            Assert.AreEqual(Verdict.Suspect, historique[0].Verdict);
            Assert.IsTrue(historique[0].Details.Contains("indice de test"));
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }

    [TestMethod]
    public async Task Le_cache_renvoie_la_derniere_analyse_d_un_hash()
    {
        string racine = NouveauDossier();
        try
        {
            var depot = new SqliteScanRepository(Path.Combine(racine, "antivirus.db"));
            await depot.SaveScanAsync(NouveauResultat(@"C:\test\b.exe", "bbb", 10, Verdict.Sain));
            await depot.SaveScanAsync(NouveauResultat(@"C:\test\b.exe", "bbb", 80, Verdict.Malveillant));

            var derniere = await depot.GetLastScanByHashAsync("bbb");
            var inconnue = await depot.GetLastScanByHashAsync("zzz");

            Assert.IsNotNull(derniere);
            Assert.AreEqual(80, derniere.Score);
            Assert.IsNull(inconnue);
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }

    [TestMethod]
    public async Task La_liste_blanche_ajoute_et_retire_un_hash()
    {
        string racine = NouveauDossier();
        try
        {
            var depot = new SqliteScanRepository(Path.Combine(racine, "antivirus.db"));

            Assert.IsFalse(await depot.IsWhitelistedAsync("abc"));

            await depot.AddToWhitelistAsync("ABC", @"C:\test\c.exe");
            Assert.IsTrue(await depot.IsWhitelistedAsync("abc"));

            await depot.RemoveFromWhitelistAsync("abc");
            Assert.IsFalse(await depot.IsWhitelistedAsync("abc"));
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }
}