using AntivirusIA.Core.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

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
        Indicators = outcome.Result.Indicators.Select(i => $"[{i.Source}] {i.Description} (+{i.Points})").ToList();
    }

    public string FileName => System.IO.Path.GetFileName(_outcome.Path);
    public string FullPath => _outcome.Path;
    public Verdict Verdict => _outcome.Verdict;
    public int Score => _outcome.Score;
    public bool HasError => _outcome.Error is not null;
    public string Explanation => _outcome.Explanation ?? (HasError ? $"Analyse impossible : {_outcome.Error}" : "Aucun indice de menace détecté.");
    public string ExplanationSource => HasError ? "Erreur" : _outcome.ExplanationFromAi ? "Explication de l'IA locale" : "Explication des moteurs locaux";
    public bool ExplanationFromAi => _outcome.ExplanationFromAi;
    public string? Family => _outcome.Ai?.Family;
    public string AiConfidenceText => _outcome.Ai is { } a ? $"Confiance de l'IA : {a.Confidence} %" : string.Empty;
    public IReadOnlyList<string> Indicators { get; }
    public bool CanQuarantine => Verdict != Verdict.Sain && !IsQuarantined && !HasError;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanQuarantine))]
    [NotifyCanExecuteChangedFor(nameof(QuarantineCommand))]
    private bool _isQuarantined;

    [ObservableProperty] private bool _isExpanded;

    [RelayCommand(CanExecute = nameof(CanQuarantine))]
    private async Task QuarantineAsync()
    {
        if (await _scan.QuarantineAsync(_outcome))
            IsQuarantined = true;
    }
}
