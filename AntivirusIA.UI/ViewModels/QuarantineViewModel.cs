using System.Collections.ObjectModel;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

/// <summary>Ligne de la liste de quarantaine.</summary>
public sealed record QuarantineRow(QuarantineEntry Entry)
{
    public string FileName => Path.GetFileName(Entry.OriginalPath);
    public string OriginalPath => Entry.OriginalPath;
    public string Reason => Entry.Reason;
    public string DateText => Entry.DateUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm");
    public string SizeText => FormatSize(Entry.SizeBytes);

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} o",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} Ko",
        _ => $"{bytes / 1024.0 / 1024.0:0.#} Mo"
    };
}

public sealed partial class QuarantineViewModel(IQuarantineService quarantine, IDialogService dialogs, AlertHub alerts, ActivityStats stats)
    : ObservableObject, IPageViewModel
{
    public ObservableCollection<QuarantineRow> Items { get; } = new();

    [ObservableProperty] private string _message = string.Empty;

    public Task OnNavigatedToAsync()
    {
        Refresh();
        return Task.CompletedTask;
    }

    [RelayCommand]
    private void Refresh()
    {
        Items.Clear();
        foreach (var entry in quarantine.List().OrderByDescending(e => e.DateUtc))
            Items.Add(new QuarantineRow(entry));
        stats.Quarantined = Items.Count;
    }

    [RelayCommand]
    private async Task RestoreAsync(QuarantineRow? row)
    {
        if (row is null) return;
        if (!dialogs.Confirm("Restaurer le fichier",
                $"« {row.FileName} » sera restauré à son emplacement d'origine. Il a été jugé dangereux : ne le restaurez que si vous êtes certain qu'il est sûr.",
                "Restaurer", danger: true)) return;
        try
        {
            await quarantine.RestoreAsync(row.Entry.Id);
            Message = $"« {row.FileName} » restauré.";
            alerts.Publish(AlertSeverity.Info, "Quarantaine", "Fichier restauré", row.FileName);
            Refresh();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Message = $"Restauration impossible : {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task DeleteAsync(QuarantineRow? row)
    {
        if (row is null) return;
        if (!dialogs.Confirm("Supprimer définitivement",
                $"« {row.FileName} » sera supprimé définitivement de la quarantaine. Cette action est irréversible.",
                "Supprimer", danger: true)) return;
        try
        {
            await quarantine.DeleteAsync(row.Entry.Id);
            Message = $"« {row.FileName} » supprimé.";
            Refresh();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Message = $"Suppression impossible : {ex.Message}";
        }
    }
}
