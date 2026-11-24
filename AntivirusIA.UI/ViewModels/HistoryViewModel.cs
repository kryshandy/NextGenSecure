using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

/// <summary>Ligne d'historique. Le chemin et les détails proviennent de fichiers analysés : affichage en texte brut.</summary>
public sealed record HistoryRow(ScanRecord Record)
{
    public string FileName => Path.GetFileName(Record.Path);
    public string FullPath => Record.Path;
    public Verdict Verdict => Record.Verdict;
    public int Score => Record.Score;
    public string DateText => Record.DateUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss");
    public string Details => string.IsNullOrWhiteSpace(Record.Details) ? "Aucun indice détecté." : Record.Details;
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
    [ObservableProperty] private int _visibleCount;
    [ObservableProperty] private string _error = string.Empty;

    partial void OnFilterTextChanged(string value)
    {
        View.Refresh();
        VisibleCount = View.Cast<object>().Count();
    }

    public Task OnNavigatedToAsync() => LoadAsync();

    [RelayCommand]
    private async Task LoadAsync()
    {
        try
        {
            var records = await _repository.GetHistoryAsync(500);
            Rows.Clear();
            foreach (var r in records) Rows.Add(new HistoryRow(r));
            Error = string.Empty;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Error = $"Historique indisponible : {ex.Message}";
        }
        VisibleCount = View.Cast<object>().Count();
    }

    private bool Matches(HistoryRow row) =>
        string.IsNullOrWhiteSpace(FilterText) ||
        row.FullPath.Contains(FilterText, StringComparison.OrdinalIgnoreCase) ||
        row.Verdict.ToString().Contains(FilterText, StringComparison.OrdinalIgnoreCase);
}
