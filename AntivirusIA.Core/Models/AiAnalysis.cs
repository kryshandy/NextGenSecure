namespace AntivirusIA.Core.Models;

// Réponse analysée de l'IA
public sealed record AiAnalysis(Verdict Verdict, int Confidence, string Explanation, string? Family);