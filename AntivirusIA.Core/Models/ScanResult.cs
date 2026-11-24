namespace AntivirusIA.Core.Models;

public sealed class ScanResult
{
    // Une signature numérique valide divise par 4 le poids des heuristiques (installeurs packés, débogueurs...)
    public const int TrustedHeuristicDivisor = 4;

    public required FileReport File { get; init; }
    public List<Indicator> Indicators { get; } = new();
    public List<string> Warnings { get; } = new();

    // Signature numérique du fichier (null = non vérifiée)
    public FileTrust? Trust { get; set; }

    // Vrai si un moteur a échoué de façon inattendue : le verdict repose sur une analyse partielle
    public bool Incomplete { get; set; }

    // Score de risque de 0 à 100 :
    // - les indices définitifs (hash connu, règle caractéristique) comptent toujours en totalité ;
    // - les heuristiques sont atténuées si le fichier porte une signature valide.
    public int Score
    {
        get
        {
            int definitive = Indicators.Where(i => i.Definitive).Sum(i => i.Points);
            int heuristic = Indicators.Where(i => !i.Definitive).Sum(i => i.Points);
            if (Trust?.IsTrusted == true)
                heuristic /= TrustedHeuristicDivisor;
            return Math.Clamp(definitive + heuristic, 0, 100);
        }
    }

    public Verdict Verdict { get; set; } = Verdict.Sain;
    public string? Explanation { get; set; }
}
