using System.Diagnostics;
using System.Text.Json;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

namespace AntivirusIA.Ml;

/// <summary>Métadonnées du modèle (écrites par l'entraînement, à côté du fichier .onnx).</summary>
public sealed record EmberModelInfo(
    int Features,
    double ThresholdLow,
    double ThresholdHigh,
    double TestAuc,
    double TestFprLow,
    double TestTprLow,
    double TestFprHigh,
    double TestTprHigh,
    int TrainSamples,
    int TestSamples,
    string TrainedOn,
    string Version);

/// <summary>
/// IA niveau 1 : classifieur statique des exécutables Windows (PE). Les 616 caractéristiques EMBER
/// (<see cref="EmberFeatures"/>) passent dans un modèle LightGBM exporté en ONNX, exécuté par ONNX Runtime, 100 % local.
/// Deux seuils fixés sur le jeu de test EMBER : « élevé » (≈ 0,1 % de faux positifs) et « bas » (≈ 1 %).
/// L'indice est heuristique : il est atténué si le fichier porte une signature numérique valide.
/// </summary>
public sealed class EmberOnnxEngine : IDetectionEngine, IDisposable
{
    public const int PointsHigh = 40;
    public const int PointsLow = 20;
    public const long MaxBytes = 64L * 1024 * 1024;

    private readonly InferenceSession _session;
    private readonly string _inputName;
    private readonly EmberModelInfo _info;

    public EmberOnnxEngine(string modelPath)
    {
        _session = new InferenceSession(modelPath, new SessionOptions { IntraOpNumThreads = 1 });
        _inputName = _session.InputMetadata.Keys.First();
        string infoPath = Path.ChangeExtension(modelPath, ".json");
        _info = JsonSerializer.Deserialize<EmberModelInfo>(File.ReadAllText(infoPath), JsonOptions)
                ?? throw new InvalidDataException("Métadonnées du modèle illisibles.");
        if (_info.Features != EmberFeatures.Count) throw new InvalidDataException("Modèle incompatible avec les caractéristiques calculées.");
    }

    /// <summary>Crée le moteur si le modèle est livré ; null sinon (le pipeline fonctionne sans).</summary>
    public static EmberOnnxEngine? TryCreate(string modelPath)
    {
        try { return File.Exists(modelPath) ? new EmberOnnxEngine(modelPath) : null; }
        catch (Exception ex) when (ex is OnnxRuntimeException or IOException or InvalidDataException or JsonException) { return null; }
    }

    public string Name => "IA niveau 1 (EMBER / ONNX)";

    public EmberModelInfo Info => _info;

    /// <summary>Probabilité de malveillance d'un contenu PE (0 à 1) et temps de calcul.</summary>
    public (float Probability, double Milliseconds) Predict(ReadOnlySpan<byte> bytes)
    {
        var sw = Stopwatch.StartNew();
        float[] features = EmberFeatures.Extract(bytes);
        float p = Predict(features);
        return (p, sw.Elapsed.TotalMilliseconds);
    }

    /// <summary>Probabilité pour un vecteur déjà calculé (tests de parité, évaluation).</summary>
    public float Predict(float[] features)
    {
        var tensor = new DenseTensor<float>(features, [1, features.Length]);
        using var results = _session.Run([NamedOnnxValue.CreateFromTensor(_inputName, tensor)]);
        // Sortie « probabilities » [1, 2] (classe 0 = sain, 1 = malveillant)
        var probabilities = results.First(r => r.Name.Contains("prob", StringComparison.OrdinalIgnoreCase)).AsTensor<float>();
        return probabilities[0, 1];
    }

    public async Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default)
    {
        if (report.SizeBytes < 64 || report.SizeBytes > MaxBytes || !File.Exists(report.FullPath)) return [];
        byte[] bytes = await File.ReadAllBytesAsync(report.FullPath, ct);
        if (bytes.Length < 64 || bytes[0] != (byte)'M' || bytes[1] != (byte)'Z') return []; // exécutables PE uniquement

        var (p, ms) = Predict(bytes);
        int points = p >= _info.ThresholdHigh ? PointsHigh : p >= _info.ThresholdLow ? PointsLow : 0;
        if (points == 0) return [];
        string level = points == PointsHigh ? "très probablement malveillant" : "ressemble à un malware";
        return [new Indicator(Name, $"Modèle statique : {level} (probabilité {p:P0}, {ms:0} ms)", points)];
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public void Dispose() => _session.Dispose();
}
