using System.Security.Cryptography;
using AntivirusIA.Core.Models;
using AntivirusIA.Engines;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class EntropyAnalyzerTests
{
    [TestMethod]
    public async Task Contenu_repetitif_a_une_entropie_nulle()
    {
        string chemin = Path.GetTempFileName();
        await File.WriteAllBytesAsync(chemin, new byte[4096]);

        double entropie = await EntropyAnalyzer.ComputeEntropyAsync(chemin);
        File.Delete(chemin);

        Assert.AreEqual(0.0, entropie, 0.001);
    }

    [TestMethod]
    public async Task Donnees_aleatoires_dans_un_programme_sont_signalees()
    {
        string chemin = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".dll");
        await File.WriteAllBytesAsync(chemin, RandomNumberGenerator.GetBytes(65536));

        var rapport = new FileReport { FullPath = chemin, SizeBytes = new FileInfo(chemin).Length };
        var indices = await new EntropyAnalyzer().AnalyzeAsync(rapport);
        File.Delete(chemin);

        Assert.AreEqual(1, indices.Count);
        Assert.AreEqual(15, indices[0].Points);
    }

    [TestMethod]
    public async Task Fichier_non_executable_n_est_pas_signale()
    {
        string chemin = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        await File.WriteAllBytesAsync(chemin, RandomNumberGenerator.GetBytes(65536));

        var rapport = new FileReport { FullPath = chemin, SizeBytes = new FileInfo(chemin).Length };
        var indices = await new EntropyAnalyzer().AnalyzeAsync(rapport);
        File.Delete(chemin);

        Assert.AreEqual(0, indices.Count);
    }
}