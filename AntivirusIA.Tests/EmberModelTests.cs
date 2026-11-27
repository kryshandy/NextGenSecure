using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using AntivirusIA.Core.Models;
using AntivirusIA.Ml;

namespace AntivirusIA.Tests;

/// <summary>
/// IA niveau 1 : parité de l'extraction C# avec l'algorithme de référence EMBER (Python), parité de la probabilité
/// ONNX, budget de temps, et comportement du moteur dans le pipeline.
/// </summary>
[TestClass]
public sealed class EmberModelTests
{
    private static string ModelPath => Path.Combine(AppContext.BaseDirectory, "Models", "ember-subset.onnx");
    private static string ParityPath => Path.Combine(AppContext.BaseDirectory, "Data", "ember-parity.json");

    private static EmberOnnxEngine Engine()
    {
        if (!File.Exists(ModelPath)) Assert.Inconclusive("Modèle non entraîné (scripts/ml/train_ember_subset.py).");
        return new EmberOnnxEngine(ModelPath);
    }

    [TestMethod]
    public void Vecteur_de_616_valeurs_normalisees()
    {
        var v = EmberFeatures.Extract(File.ReadAllBytes(Path.Combine(Environment.SystemDirectory, "notepad.exe")));
        Assert.HasCount(EmberFeatures.Count, v);
        Assert.AreEqual(1.0, v.Take(256).Sum(), 1e-4, "histogramme normalisé");
        Assert.AreEqual(1.0, v.Skip(256).Take(256).Sum(), 1e-4, "histogramme d'entropie normalisé");
        Assert.IsGreaterThan(10f, v[512], "nombre de chaînes");
    }

    [TestMethod]
    public void Fichier_vide_ou_minuscule_sans_erreur()
    {
        Assert.HasCount(EmberFeatures.Count, EmberFeatures.Extract([]));
        Assert.HasCount(EmberFeatures.Count, EmberFeatures.Extract("MZ"u8));
    }

    [TestMethod]
    public void Parite_avec_la_reference_EMBER_et_le_modele_python()
    {
        if (!File.Exists(ParityPath)) Assert.Inconclusive("Fichier de parité absent (généré par l'entraînement).");
        using var engine = Engine();
        using var doc = JsonDocument.Parse(File.ReadAllText(ParityPath));
        int compared = 0;
        foreach (var sample in doc.RootElement.GetProperty("samples").EnumerateArray())
        {
            string path = sample.GetProperty("path").GetString()!;
            if (!File.Exists(path)) continue;
            byte[] bytes = File.ReadAllBytes(path);
            if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != sample.GetProperty("sha256").GetString()) continue; // autre version de Windows
            float[] expected = sample.GetProperty("features").EnumerateArray().Select(e => (float)e.GetDouble()).ToArray();
            float[] actual = EmberFeatures.Extract(bytes);
            for (int i = 0; i < EmberFeatures.Count; i++)
                Assert.AreEqual(expected[i], actual[i], Math.Max(1e-5, Math.Abs(expected[i]) * 1e-5), $"{Path.GetFileName(path)} : caractéristique {i}");
            Assert.AreEqual(sample.GetProperty("probability").GetDouble(), engine.Predict(actual), 1e-4, $"{Path.GetFileName(path)} : probabilité");
            compared++;
        }
        if (compared == 0) Assert.Inconclusive("Aucun exécutable de référence identique sur cette machine.");
    }

    [TestMethod]
    public void Budget_de_temps_sous_50_ms_pour_un_executable_de_2_Mo()
    {
        using var engine = Engine();
        byte[] bytes = File.ReadAllBytes(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        engine.Predict(bytes); // chauffe
        var sw = Stopwatch.StartNew();
        const int runs = 5;
        for (int i = 0; i < runs; i++) engine.Predict(bytes);
        double ms = sw.Elapsed.TotalMilliseconds / runs;
        Assert.IsLessThan(50.0, ms, $"{ms:0.0} ms pour {bytes.Length / 1024} Ko");
    }

    [TestMethod]
    public async Task Executables_Windows_signes_pas_signales_et_non_PE_ignores()
    {
        using var engine = Engine();
        foreach (string name in new[] { "notepad.exe", "cmd.exe", "ping.exe" })
        {
            string path = Path.Combine(Environment.SystemDirectory, name);
            var report = new FileReport { FullPath = path, SizeBytes = new FileInfo(path).Length };
            var indicators = await engine.AnalyzeAsync(report);
            Assert.AreEqual(0, indicators.Sum(i => i.Points), name);
        }
        string text = Path.GetTempFileName();
        await File.WriteAllTextAsync(text, new string('a', 5000));
        try
        {
            Assert.IsEmpty(await engine.AnalyzeAsync(new FileReport { FullPath = text, SizeBytes = 5000 }), "non PE ignoré");
        }
        finally { File.Delete(text); }
    }
}
