using System.Collections.ObjectModel;
using AntivirusIA.Core.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

public sealed partial class ScanViewModel(ScanService scan, IDialogService dialogs) : ObservableObject
{
    private CancellationTokenSource? _cts;

    public ObservableCollection<ScanItemViewModel> Results { get; } = new();

    [ObservableProperty] private string _selectedPath = string.Empty;
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty] private string _progressText = string.Empty;
    [ObservableProperty] private string _summary = string.Empty;
    [ObservableProperty] private bool _hasResults;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartScanCommand))]
    [NotifyCanExecuteChangedFor(nameof(PickFileCommand))]
    [NotifyCanExecuteChangedFor(nameof(PickFolderCommand))]
    private bool _isScanning;

    /// <summary>Message sur l'état de l'IA locale (affiché sous la zone de dépôt).</summary>
    public string AiStatus => scan.AiAvailable switch
    {
        true => "IA locale opérationnelle : les verdicts douteux sont expliqués.",
        false => "Modèle IA indisponible : verdict des moteurs locaux uniquement.",
        _ => "L'IA locale explique les fichiers suspects ou malveillants (chargée à la demande)."
    };

    private bool CanStart() => !IsScanning;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private void PickFile()
    {
        string? path = dialogs.PickFile("Choisir un fichier à analyser");
        if (path is not null) SelectedPath = path;
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private void PickFolder()
    {
        string? path = dialogs.PickFolder("Choisir un dossier à analyser");
        if (path is not null) SelectedPath = path;
    }

    /// <summary>Appelé aussi par le glisser-déposer de la vue.</summary>
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
        HasResults = false;
        Summary = string.Empty;
        ProgressPercent = 0;
        ProgressText = "Préparation...";
        IsScanning = true;

        // Progress<T> capture le contexte UI : les rappels arrivent sur le thread UI
        var progress = new Progress<ScanProgress>(p =>
        {
            ProgressPercent = p.Total == 0 ? 0 : 100.0 * p.Done / p.Total;
            ProgressText = p.Current.Length == 0
                ? $"{p.Done} / {p.Total} fichiers"
                : $"{p.Done} / {p.Total} - {System.IO.Path.GetFileName(p.Current)}";
        });
        var results = new Progress<ScanOutcome>(o =>
        {
            Results.Add(new ScanItemViewModel(o, scan));
            HasResults = true;
        });

        try
        {
            await scan.ScanPathAsync(SelectedPath, progress, results, _cts.Token);
            // Laisse les derniers rappels Progress<T> (postés sur le thread UI) s'exécuter avant le résumé
            await Task.Yield();
            int threats = Results.Count(r => r.Verdict != Verdict.Sain);
            Summary = threats == 0
                ? $"{Results.Count} fichier(s) analysé(s) : aucune menace détectée."
                : $"{Results.Count} fichier(s) analysé(s) : {threats} menace(s) à examiner.";
        }
        catch (OperationCanceledException)
        {
            Summary = "Analyse annulée.";
        }
        catch (FileNotFoundException)
        {
            Summary = "Le chemin sélectionné est introuvable.";
        }
        finally
        {
            SortResults();
            IsScanning = false;
            ProgressText = string.Empty;
            OnPropertyChanged(nameof(AiStatus));
            _cts.Dispose();
            _cts = null;
        }
    }

    // Menaces en tête de liste, puis par score décroissant
    private void SortResults()
    {
        var sorted = Results.OrderByDescending(r => r.Verdict).ThenByDescending(r => r.Score).ToList();
        for (int i = 0; i < sorted.Count; i++)
            Results.Move(Results.IndexOf(sorted[i]), i);
    }

    [RelayCommand]
    private void Cancel() => _cts?.Cancel();

    [RelayCommand]
    private void Clear()
    {
        Results.Clear();
        HasResults = false;
        Summary = string.Empty;
        SelectedPath = string.Empty;
    }
}
