using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Data;
using System.Windows.Threading;
using AntivirusIA.Core.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

/// <summary>Filtre des résultats par verdict.</summary>
public enum ResultFilter { All, Malicious, Suspect, Healthy }

/// <summary>Critère de tri des résultats.</summary>
public enum ResultSort { Severity, Score, Name }

public sealed partial class ScanViewModel : ObservableObject
{
    private readonly ScanService _scan;
    private readonly IDialogService _dialogs;
    private readonly DispatcherTimer _clock;
    private readonly Stopwatch _stopwatch = new();
    private CancellationTokenSource? _cts;

    public ScanViewModel(ScanService scan, IDialogService dialogs)
    {
        _scan = scan;
        _dialogs = dialogs;

        // Vue privée des résultats : filtrable et triable sans toucher à la collection source
        ResultsView = new ListCollectionView(Results);
        ResultsView.Filter = o => o is ScanItemViewModel r && Matches(r);
        ApplySort();

        // Chronomètre affiché pendant l'analyse
        _clock = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clock.Tick += (_, _) => ElapsedText = FormatElapsed(_stopwatch.Elapsed);
    }

    public ObservableCollection<ScanItemViewModel> Results { get; } = new();
    public ICollectionView ResultsView { get; }

    [ObservableProperty] private string _selectedPath = string.Empty;
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty] private string _progressText = string.Empty;
    [ObservableProperty] private string _currentFile = string.Empty;
    [ObservableProperty] private int _filesDone;
    [ObservableProperty] private int _filesTotal;
    [ObservableProperty] private string _elapsedText = "00:00";
    [ObservableProperty] private string _summary = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState))]
    private bool _hasResults;
    [ObservableProperty] private ProtectionLevel _summaryLevel = ProtectionLevel.Protected;

    // Compteurs par verdict (puces de filtre)
    [ObservableProperty] private int _countAll;
    [ObservableProperty] private int _countMalicious;
    [ObservableProperty] private int _countSuspect;
    [ObservableProperty] private int _countHealthy;
    [ObservableProperty] private int _visibleCount;

    [ObservableProperty] private ResultFilter _filter = ResultFilter.All;
    [ObservableProperty] private ResultSort _sort = ResultSort.Severity;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartScanCommand))]
    [NotifyCanExecuteChangedFor(nameof(PickFileCommand))]
    [NotifyCanExecuteChangedFor(nameof(PickFolderCommand))]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState))]
    private bool _isScanning;

    /// <summary>État vide : ni analyse en cours, ni résultat à afficher.</summary>
    public bool ShowEmptyState => !HasResults && !IsScanning;

    /// <summary>Vrai quand une analyse est terminée (ou annulée) et qu'un résumé est à afficher.</summary>
    [ObservableProperty] private bool _showSummary;

    /// <summary>Menaces (suspects + malveillants) trouvées jusqu'ici.</summary>
    public int ThreatCount => CountMalicious + CountSuspect;

    /// <summary>Message sur l'état de l'IA locale (affiché sous la zone de dépôt).</summary>
    public string AiStatus => _scan.AiAvailable switch
    {
        true => "IA locale opérationnelle : les verdicts douteux sont expliqués.",
        false => "Modèle IA indisponible : verdict des moteurs locaux uniquement.",
        _ => "L'IA locale explique les fichiers suspects ou malveillants (chargée à la demande)."
    };

    partial void OnFilterChanged(ResultFilter value) => RefreshView();
    partial void OnSortChanged(ResultSort value) => ApplySort();

    private bool Matches(ScanItemViewModel r) => Filter switch
    {
        ResultFilter.Malicious => r.Verdict == Verdict.Malveillant,
        ResultFilter.Suspect => r.Verdict == Verdict.Suspect,
        ResultFilter.Healthy => r.Verdict == Verdict.Sain,
        _ => true
    };

    private void RefreshView()
    {
        ResultsView.Refresh();
        VisibleCount = Results.Count(Matches);
    }

    private void ApplySort()
    {
        using (ResultsView.DeferRefresh())
        {
            ResultsView.SortDescriptions.Clear();
            switch (Sort)
            {
                case ResultSort.Score:
                    ResultsView.SortDescriptions.Add(new SortDescription(nameof(ScanItemViewModel.Score), ListSortDirection.Descending));
                    break;
                case ResultSort.Name:
                    ResultsView.SortDescriptions.Add(new SortDescription(nameof(ScanItemViewModel.FileName), ListSortDirection.Ascending));
                    break;
                default:
                    // Menaces en tête, puis par score décroissant
                    ResultsView.SortDescriptions.Add(new SortDescription(nameof(ScanItemViewModel.Verdict), ListSortDirection.Descending));
                    ResultsView.SortDescriptions.Add(new SortDescription(nameof(ScanItemViewModel.Score), ListSortDirection.Descending));
                    break;
            }
        }
    }

    private void AddResult(ScanOutcome outcome)
    {
        var item = new ScanItemViewModel(outcome, _scan);
        Results.Add(item);
        HasResults = true;

        CountAll++;
        switch (item.Verdict)
        {
            case Verdict.Malveillant: CountMalicious++; break;
            case Verdict.Suspect: CountSuspect++; break;
            default: CountHealthy++; break;
        }
        OnPropertyChanged(nameof(ThreatCount));
        if (Matches(item)) VisibleCount++;
    }

    private void ResetCounters()
    {
        CountAll = CountMalicious = CountSuspect = CountHealthy = VisibleCount = 0;
        OnPropertyChanged(nameof(ThreatCount));
    }

    private bool CanStart() => !IsScanning;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private void PickFile()
    {
        string? path = _dialogs.PickFile("Choisir un fichier à analyser");
        if (path is not null) SelectedPath = path;
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private void PickFolder()
    {
        string? path = _dialogs.PickFolder("Choisir un dossier à analyser");
        if (path is not null) SelectedPath = path;
    }

    /// <summary>Appelé aussi par le glisser-déposer de la vue et par l'analyse rapide du tableau de bord.</summary>
    public async Task ScanPathAsync(string path)
    {
        if (IsScanning) return;
        SelectedPath = path;
        await StartScanAsync();
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task StartScanAsync()
    {
        if (string.IsNullOrWhiteSpace(SelectedPath)) return;

        _cts = new CancellationTokenSource();
        Results.Clear();
        ResetCounters();
        Filter = ResultFilter.All;
        HasResults = false;
        ShowSummary = false;
        Summary = string.Empty;
        ProgressPercent = 0;
        FilesDone = 0;
        FilesTotal = 0;
        CurrentFile = string.Empty;
        ProgressText = "Préparation...";
        ElapsedText = "00:00";
        IsScanning = true;
        _stopwatch.Restart();
        _clock.Start();

        // Progress<T> capture le contexte UI : les rappels arrivent sur le thread UI
        var progress = new Progress<ScanProgress>(p =>
        {
            ProgressPercent = p.Total == 0 ? 0 : 100.0 * p.Done / p.Total;
            FilesDone = p.Done;
            FilesTotal = p.Total;
            CurrentFile = p.Current.Length == 0 ? string.Empty : p.Current;
            ProgressText = p.Current.Length == 0
                ? $"{p.Done} / {p.Total} fichiers"
                : $"{p.Done} / {p.Total} - {System.IO.Path.GetFileName(p.Current)}";
        });
        var results = new Progress<ScanOutcome>(AddResult);

        try
        {
            await _scan.ScanPathAsync(SelectedPath, progress, results, _cts.Token);
            // Laisse les derniers rappels Progress<T> (postés sur le thread UI) s'exécuter avant le résumé
            await Task.Yield();
            int threats = ThreatCount;
            Summary = threats == 0
                ? $"{Results.Count} fichier(s) analysé(s) : aucune menace détectée."
                : $"{Results.Count} fichier(s) analysé(s) : {threats} menace(s) à examiner.";
            SummaryLevel = CountMalicious > 0 ? ProtectionLevel.Danger : threats > 0 ? ProtectionLevel.Attention : ProtectionLevel.Protected;
        }
        catch (OperationCanceledException)
        {
            Summary = "Analyse annulée.";
            SummaryLevel = ProtectionLevel.Attention;
        }
        catch (FileNotFoundException)
        {
            Summary = "Le chemin sélectionné est introuvable.";
            SummaryLevel = ProtectionLevel.Attention;
        }
        finally
        {
            _clock.Stop();
            _stopwatch.Stop();
            ElapsedText = FormatElapsed(_stopwatch.Elapsed);
            IsScanning = false;
            ShowSummary = true;
            ProgressText = string.Empty;
            CurrentFile = string.Empty;
            OnPropertyChanged(nameof(AiStatus));
            _cts.Dispose();
            _cts = null;
        }
    }

    private static string FormatElapsed(TimeSpan t) =>
        t.TotalHours >= 1 ? t.ToString(@"h\:mm\:ss") : t.ToString(@"mm\:ss");

    [RelayCommand]
    private void Cancel() => _cts?.Cancel();

    [RelayCommand]
    private void Clear()
    {
        Results.Clear();
        ResetCounters();
        HasResults = false;
        ShowSummary = false;
        Summary = string.Empty;
        SelectedPath = string.Empty;
    }
}
