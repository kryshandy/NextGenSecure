namespace AntivirusIA.Core.Models;

public sealed class ScanResult
{
    public required FileReport File { get; init; }
    public List<Indicator> Indicators { get; } = new();
    public List<string> Warnings { get; } = new();

    // Score de risque de 0 à 100, calculé à partir des indices
    public int Score => Math.Min(100, Indicators.Sum(i => i.Points));

    public Verdict Verdict { get; set; } = Verdict.Sain;
    public string? Explanation { get; set; }
}