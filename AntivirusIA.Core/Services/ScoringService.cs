using AntivirusIA.Core.Models;

namespace AntivirusIA.Core.Services;

public sealed class ScoringService
{
    public int SeuilSuspect { get; init; } = 30;
    public int SeuilMalveillant { get; init; } = 70;

    public Verdict Evaluate(int score)
    {
        if (score >= SeuilMalveillant) return Verdict.Malveillant;
        if (score >= SeuilSuspect) return Verdict.Suspect;
        return Verdict.Sain;
    }
}