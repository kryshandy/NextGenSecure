using System.Diagnostics;
using AntivirusIA.Ai;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;
using AntivirusIA.Core.Services;
using AntivirusIA.UI.Models;

namespace AntivirusIA.UI.Services;

/// <summary>Résultat d'analyse d'un fichier, enrichi de l'explication (IA ou locale).</summary>
public sealed record ScanOutcome(
    ScanResult Result,
    string? Explanation,
    bool ExplanationFromAi,
    AiAnalysis? Ai,
    bool Quarantined,
    string? Error)
{
    public Verdict Verdict => Result.Verdict;
    public int Score => Result.Score;
    public string Path => Result.File.FullPath;
}

public sealed record ScanProgress(int Done, int Total, string Current);

/// <summary>
/// Service applicatif : ScanPipeline (verdict local) -> IA locale pour expliquer si le verdict n'est pas Sain
/// -> persistance dans l'historique. Si le modèle est absent, on retombe silencieusement sur le verdict local.
/// </summary>
public sealed class ScanService
{
    private const int MaxFiles = 50_000;
    private const int MaxAiPerRun = 5;
    private static readonly TimeSpan AiTimeout = TimeSpan.FromSeconds(90);

    private readonly ScanPipeline _pipeline;
    private readonly IAiProvider _ai;
    private readonly IScanRepository _repository;
    private readonly IQuarantineService _quarantine;
    private readonly AppSettings _settings;
    private readonly AlertHub _alerts;
    private readonly ActivityStats _stats;

    public ScanService(ScanPipeline pipeline, IAiProvider ai, IScanRepository repository, IQuarantineService quarantine,
        AppSettings settings, AlertHub alerts, ActivityStats stats)
    {
        _pipeline = pipeline;
        _ai = ai;
        _repository = repository;
        _quarantine = quarantine;
        _settings = settings;
        _alerts = alerts;
        _stats = stats;
    }

    /// <summary>null = inconnu, true = IA opérationnelle, false = modèle absent/indisponible (verdict local seul).</summary>
    public bool? AiAvailable { get; private set; }

    /// <summary>Analyse un fichier unique (utilisé aussi par la surveillance des téléchargements).</summary>
    public Task<ScanOutcome> ScanFileAsync(string path, CancellationToken ct = default) =>
        Task.Run(() => ScanOneAsync(path, new AiBudget(MaxAiPerRun), ct), ct);

    /// <summary>
    /// Analyse un fichier ou un dossier (récursif, sans suivre les liens symboliques).
    /// Les résultats sont remontés via <paramref name="results"/> et la progression via <paramref name="progress"/>.
    /// </summary>
    public Task ScanPathAsync(string path, IProgress<ScanProgress>? progress, IProgress<ScanOutcome>? results, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var files = Enumerate(path);
            var budget = new AiBudget(MaxAiPerRun);

            for (int i = 0; i < files.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                progress?.Report(new ScanProgress(i, files.Count, files[i]));
                results?.Report(await ScanOneAsync(files[i], budget, ct));
            }
            progress?.Report(new ScanProgress(files.Count, files.Count, string.Empty));
        }, ct);

    /// <summary>Met un fichier détecté en quarantaine (chiffrée) et met à jour les compteurs.</summary>
    public async Task<bool> QuarantineAsync(ScanOutcome outcome, CancellationToken ct = default)
    {
        try
        {
            string reason = $"{outcome.Verdict} (score {outcome.Score}/100)";
            await _quarantine.QuarantineAsync(outcome.Path, reason, ct);
            UiThread.Post(() => _stats.Quarantined++);
            _alerts.Publish(AlertSeverity.Info, "Quarantaine", "Fichier mis en quarantaine", System.IO.Path.GetFileName(outcome.Path));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _alerts.Publish(AlertSeverity.Warning, "Quarantaine", "Mise en quarantaine impossible", ex.Message);
            return false;
        }
    }

    private async Task<ScanOutcome> ScanOneAsync(string path, AiBudget aiBudget, CancellationToken ct)
    {
        ScanResult result;
        try
        {
            result = await _pipeline.ScanFileAsync(path, ct);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Fichier disparu ou inaccessible : on le signale sans interrompre le lot
            var vide = new ScanResult { File = new FileReport { FullPath = path } };
            return new ScanOutcome(vide, null, false, null, false, ex.Message);
        }

        // Les seuils sont réglables à chaud : on réévalue le verdict avec les réglages courants
        result.Verdict = new ScoringService
        {
            SeuilSuspect = _settings.ThresholdSuspect,
            SeuilMalveillant = _settings.ThresholdMalicious
        }.Evaluate(result.Score);

        AiAnalysis? analysis = null;
        if (result.Verdict != Verdict.Sain && _settings.UseAi && aiBudget.TryTake())
            analysis = await TryExplainAsync(result, ct);

        // Le verdict local reste la référence : la sortie du LLM, influençable par le contenu du fichier, ne sert qu'à expliquer
        string? explanation = analysis?.Explanation;
        if (string.IsNullOrWhiteSpace(explanation))
            explanation = result.Verdict == Verdict.Sain ? null : LocalExplanation(result);
        result.Explanation = explanation;

        try
        {
            await _repository.SaveScanAsync(result, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _alerts.Publish(AlertSeverity.Warning, "Historique", "Historique non enregistré", ex.Message);
        }

        bool quarantined = false;
        if (result.Verdict == Verdict.Malveillant && _settings.AutoQuarantine)
        {
            var provisoire = new ScanOutcome(result, explanation, analysis is not null, analysis, false, null);
            quarantined = await QuarantineAsync(provisoire, ct);
        }

        var outcome = new ScanOutcome(result, explanation, analysis is not null, analysis, quarantined, null);
        UiThread.Post(() =>
        {
            _stats.FilesScanned++;
            if (outcome.Verdict != Verdict.Sain) _stats.ThreatsFound++;
        });

        if (outcome.Verdict != Verdict.Sain)
        {
            _alerts.Publish(
                outcome.Verdict == Verdict.Malveillant ? AlertSeverity.Critical : AlertSeverity.Warning,
                "Analyse",
                $"{outcome.Verdict} : {System.IO.Path.GetFileName(outcome.Path)}",
                $"Score {outcome.Score}/100");
        }
        return outcome;
    }

    private async Task<AiAnalysis?> TryExplainAsync(ScanResult result, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(AiTimeout);
        try
        {
            string prompt = AiPromptBuilder.BuildUserPrompt(result.File, result.Indicators, result.Score);
            string raw = await _ai.CompleteAsync(AiPromptBuilder.SystemPrompt, prompt, timeout.Token);
            AiAnalysis? analysis = AiResponseParser.TryParse(raw);
            AiAvailable = true;
            return analysis;
        }
        catch (FileNotFoundException)
        {
            // Modèle GGUF absent : repli silencieux sur le verdict local
            AiAvailable = false;
            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null; // délai dépassé : verdict local
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Backend natif indisponible, mémoire insuffisante... : l'IA est optionnelle
            Debug.WriteLine($"[CoreGuard] IA indisponible : {ex.GetType().Name}");
            AiAvailable = false;
            return null;
        }
    }

    // Explication de repli construite à partir des indices des moteurs locaux
    private static string LocalExplanation(ScanResult result)
    {
        string top = string.Join(" ; ", result.Indicators.OrderByDescending(i => i.Points).Take(3).Select(i => i.Description));
        string trust = result.Trust?.IsTrusted == true
            ? $" Fichier signé numériquement{(result.Trust.Publisher is { } p ? $" par {p}" : "")} : heuristiques atténuées."
            : "";
        string partial = result.Incomplete ? " Analyse partielle (un moteur n'a pas pu lire ou traiter le fichier)." : "";
        return $"Verdict établi par les moteurs locaux (score {result.Score}/100). Indices principaux : {top}.{trust}{partial}";
    }

    private static List<string> Enumerate(string path)
    {
        if (File.Exists(path)) return [System.IO.Path.GetFullPath(path)];
        if (!Directory.Exists(path)) throw new FileNotFoundException("Chemin introuvable", path);

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        };
        return Directory.EnumerateFiles(path, "*", options).Take(MaxFiles).ToList();
    }

    // Plafond d'appels IA par lot : le LLM local est lent (CPU)
    private sealed class AiBudget(int max)
    {
        private int _left = max;
        public bool TryTake() => Interlocked.Decrement(ref _left) >= 0;
    }
}
