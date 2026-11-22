using AntivirusIA.Core.Models;
using AntivirusIA.Engines;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class HeuristicEngineTests
{
    private static async Task<IReadOnlyList<Indicator>> AnalyserAsync(string nomFichier)
    {
        string dossier = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dossier);
        string chemin = Path.Combine(dossier, nomFichier);
        try
        {
            await File.WriteAllTextAsync(chemin, "contenu de test");
            var rapport = new FileReport { FullPath = chemin, SizeBytes = new FileInfo(chemin).Length };
            return await new HeuristicEngine().AnalyzeAsync(rapport);
        }
        finally
        {
            Directory.Delete(dossier, true);
        }
    }

    [TestMethod]
    public async Task Double_extension_est_detectee()
    {
        var indices = await AnalyserAsync("facture.pdf.exe");
        Assert.IsTrue(indices.Any(i => i.Points == 25));
    }

    [TestMethod]
    public async Task Programme_normal_n_a_pas_de_double_extension()
    {
        var indices = await AnalyserAsync("setup.exe");
        Assert.IsFalse(indices.Any(i => i.Points == 25));
    }

    [TestMethod]
    public async Task Fichier_texte_ne_declenche_rien()
    {
        var indices = await AnalyserAsync("notes.txt");
        Assert.AreEqual(0, indices.Count);
    }
}