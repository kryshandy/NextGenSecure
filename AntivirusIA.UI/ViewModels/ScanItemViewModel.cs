using AntivirusIA.Core.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

/// <summary>Un indice détecté. <see cref="Definitive"/> = preuve forte (jamais atténuée par la signature numérique).</summary>
public sealed record IndicatorRow(string Source, string Description, int Points, bool Definitive)
{
    public string PointsText => Points >= 0 ? $"+{Points}" : Points.ToString();
}

/// <summary>Une ligne de résultat d'analyse. Les textes issus du fichier sont affichés en texte brut.</summary>
public sealed partial class ScanItemViewModel : ObservableObject
{
    private readonly ScanService _scan;
    private readonly ScanOutcome _outcome;

    public ScanItemViewModel(ScanOutcome outcome, ScanService scan)
    {
        _outcome = outcome;
        _scan = scan;
        IsQuarantined = outcome.Quarantined;

        // Preuves fortes d'abord, puis par points décroissants : l'essentiel est lu en premier
        Indicators = outcome.Result.Indicators
            .Select(i => new IndicatorRow(i.Source, i.Description, i.Points, i.Definitive))
            .OrderByDescending(i => i.Definitive)
            .ThenByDescending(i => i.Points)
            .ToList();
    }

    public string FileName => System.IO.Path.GetFileName(_outcome.Path);
    public string FullPath => _outcome.Path;
    public Verdict Verdict => _outcome.Verdict;
    public int Score => _outcome.Score;
    public string ScoreText => $"{Score}/100";
    public bool IsThreat => Verdict != Verdict.Sain;
    public bool HasError => _outcome.Error is not null;
    public string Explanation => _outcome.Explanation ?? (HasError ? $"Analyse impossible : {_outcome.Error}" : "Aucun indice de menace détecté.");
    public string ExplanationSource => HasError ? "Erreur" : _outcome.ExplanationFromAi ? "Explication de l'IA locale" : "Explication des moteurs locaux";
    public bool ExplanationFromAi => _outcome.ExplanationFromAi;
    public string? Family => _outcome.Ai?.Family;
    public string AiConfidenceText => _outcome.Ai is { } a ? $"Confiance de l'IA : {a.Confidence} %" : string.Empty;
    public IReadOnlyList<IndicatorRow> Indicators { get; }
    public bool HasIndicators => Indicators.Count > 0;
    public int StrongEvidenceCount => Indicators.Count(i => i.Definitive);
    public bool HasStrongEvidence => StrongEvidenceCount > 0;
    public string IndicatorsHeader => $"Indices détectés ({Indicators.Count})";
    public bool CanQuarantine => Verdict != Verdict.Sain && !IsQuarantined && !HasError;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanQuarantine))]
    [NotifyCanExecuteChangedFor(nameof(QuarantineCommand))]
    private bool _isQuarantined;

    [ObservableProperty] private bool _isExpanded;

    [RelayCommand]
    private void ToggleExpand() => IsExpanded = !IsExpanded;

    [RelayCommand(CanExecute = nameof(CanQuarantine))]
    private async Task QuarantineAsync()
    {
        if (await _scan.QuarantineAsync(_outcome))
            IsQuarantined = true;
    }
}
