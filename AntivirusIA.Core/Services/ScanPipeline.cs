using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Core.Services;

public sealed class ScanPipeline
{
    // Points ajoutés quand un moteur plante de façon inattendue : un fichier qui fait échouer l'analyse
    // ne doit pas ressortir « Sain » par défaut (principe d'échec sécurisé)
    public const int EngineFailurePoints = 15;

    private readonly List<IDetectionEngine> _moteurs;
    private readonly ScoringService _scoring;
    private readonly IFileTrustProvider? _trust;

    public ScanPipeline(IEnumerable<IDetectionEngine> moteurs, ScoringService scoring, IFileTrustProvider? trust = null)
    {
        _moteurs = moteurs.ToList();
        _scoring = scoring;
        _trust = trust;
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
                resultat.Incomplete = true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Plantage inattendu d'un moteur (fichier piégé pour faire échouer l'analyse ?) : échec sécurisé
                resultat.Warnings.Add($"{moteur.Name} : échec inattendu ({ex.GetType().Name})");
                resultat.Incomplete = true;
                resultat.Indicators.Add(new Indicator(moteur.Name,
                    "L'analyse de ce moteur a échoué sur ce fichier : résultat partiel", EngineFailurePoints));
            }
        }

        // La signature n'atténue que les heuristiques : inutile de la vérifier s'il n'y en a aucune
        if (_trust is not null && resultat.Indicators.Any(i => !i.Definitive))
        {
            try
            {
                resultat.Trust = await _trust.EvaluateAsync(rapport.FullPath, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                resultat.Trust = null; // vérification impossible : aucune atténuation
            }
        }

        resultat.Verdict = _scoring.Evaluate(resultat.Score);
        return resultat;
    }
}
