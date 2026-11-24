using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

/// <summary>Filtre de l'historique par verdict.</summary>
public enum HistoryFilter { All, Malicious, Suspect, Healthy }

/// <summary>Ligne d'historique. Le chemin et les détails proviennent de fichiers analysés : affichage en texte brut.</summary>
public sealed partial class HistoryRow(ScanRecord record) : ObservableObject
{
    public ScanRecord Record { get; } = record;
    public string FileName => Path.GetFileName(Record.Path);
    public string FullPath => Record.Path;
    public Verdict Verdict => Record.Verdict;
    public int Score => Record.Score;
    public string DateText => Record.DateUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss");
    public string Details => string.IsNullOrWhiteSpace(Record.Details) ? "Aucun indice détecté." : Record.Details;

    /// <summary>Détail déplié (indices enregistrés lors de l'analyse).</summary>
    [ObservableProperty] private bool _isExpanded;

    [RelayCommand]
    private void ToggleExpand() => IsExpanded = !IsExpanded;
}

public sealed partial class HistoryViewModel : ObservableObject, IPageViewModel
{
    private readonly IScanRepository _repository;

    public HistoryViewModel(IScanRepository repository)
    {
        _repository = repository;
        View = CollectionViewSource.GetDefaultView(Rows);
        View.Filter = o => o is HistoryRow r && Matches(r);
    }

    public ObservableCollection<HistoryRow> Rows { get; } = new();
    public ICollectionView View { get; }

    [ObservableProperty] private string _filterText = string.Empty;
    [ObservableProperty] private HistoryFilter _verdictFilter = HistoryFilter.All;
    [ObservableProperty] private int _visibleCount;
    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private string _error = string.Empty;
    [ObservableProperty] private bool _isLoading;

    partial void OnFilterTextChanged(string value) => RefreshView();
    partial void OnVerdictFilterChanged(HistoryFilter value) => RefreshView();

    private void RefreshView()
    {
        View.Refresh();
        VisibleCount = View.Cast<object>().Count();
    }

    public Task OnNavigatedToAsync() => LoadAsync();

    [RelayCommand]
    private async Task LoadAsync()
    {
        IsLoading = true;
        try
        {
            var records = await _repository.GetHistoryAsync(500);
            Rows.Clear();
            foreach (var r in records) Rows.Add(new HistoryRow(r));
            TotalCount = Rows.Count;
            Error = string.Empty;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Error = $"Historique indisponible : {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
        VisibleCount = View.Cast<object>().Count();
    }

    private bool Matches(HistoryRow row)
    {
        bool verdictOk = VerdictFilter switch
        {
            HistoryFilter.Malicious => row.Verdict == Verdict.Malveillant,
            HistoryFilter.Suspect => row.Verdict == Verdict.Suspect,
            HistoryFilter.Healthy => row.Verdict == Verdict.Sain,
            _ => true
        };
        return verdictOk && (string.IsNullOrWhiteSpace(FilterText) ||
            row.FullPath.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
            row.Verdict.ToString().Contains(FilterText, StringComparison.OrdinalIgnoreCase));
    }
}
