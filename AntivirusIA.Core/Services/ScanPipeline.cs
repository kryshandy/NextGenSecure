using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Core.Services;

public sealed class ScanPipeline
{
    private readonly List<IDetectionEngine> _moteurs;
    private readonly ScoringService _scoring;

    public ScanPipeline(IEnumerable<IDetectionEngine> moteurs, ScoringService scoring)
    {
        _moteurs = moteurs.ToList();
        _scoring = scoring;
    }

    public async Task<ScanResult> ScanFileAsync(string chemin, CancellationToken ct = default)
    {
        var info = new FileInfo(chemin);
        if (!info.Exists)
            throw new FileNotFoundException("Fichier introuvable", chemin);

        var rapport = new FileReport { FullPath = info.FullName, SizeBytes = info.Length };
        var resultat = new ScanResult { File = rapport };

        foreach (var moteur in _moteurs)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                resultat.Indicators.AddRange(await moteur.AnalyzeAsync(rapport, ct));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Fichier verrouillé ou inaccessible : on le signale et on continue
                resultat.Warnings.Add($"{moteur.Name} : {ex.Message}");
            }
        }

        resultat.Verdict = _scoring.Evaluate(resultat.Score);
        return resultat;
    }
}