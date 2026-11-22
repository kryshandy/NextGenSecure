using System.Text.Json;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Engines;

internal sealed record SignatureEntry(string Sha256, string Name);
internal sealed record SignatureFile(List<SignatureEntry>? Signatures);

public sealed class SignatureEngine : IDetectionEngine
{
    private readonly Dictionary<string, string> _knownHashes = new();

    public string Name => "Signatures";

    public SignatureEngine(string signaturesPath)
    {
        string json = File.ReadAllText(signaturesPath);
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var file = JsonSerializer.Deserialize<SignatureFile>(json, options);

        foreach (var entry in file?.Signatures ?? new List<SignatureEntry>())
            _knownHashes[entry.Sha256.ToLowerInvariant()] = entry.Name;
    }

    public async Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default)
    {
        report.Sha256 ??= await FileHasher.ComputeSha256Async(report.FullPath, ct);

        var indicators = new List<Indicator>();
        if (_knownHashes.TryGetValue(report.Sha256, out string? malwareName))
            indicators.Add(new Indicator(Name, $"Signature connue : {malwareName}", 100));

        return indicators;
    }
}