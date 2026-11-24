using System.Windows;
using AntivirusIA.UI.Views;
using Microsoft.Win32;

namespace AntivirusIA.UI.Services;

/// <summary>Dialogues applicatifs : abstraits pour que les ViewModels restent testables.</summary>
public interface IDialogService
{
    bool Confirm(string title, string message, string confirmText = "Confirmer", bool danger = false);
    string? PickFile(string title = "Choisir un fichier", string filter = "Tous les fichiers (*.*)|*.*");
    string? PickFolder(string title = "Choisir un dossier");
}

public sealed class DialogService : IDialogService
{
    public bool Confirm(string title, string message, string confirmText = "Confirmer", bool danger = false)
    {
        var dialog = new ConfirmDialog(title, message, confirmText, danger) { Owner = Application.Current.MainWindow };
        return dialog.ShowDialog() == true;
    }

    public string? PickFile(string title = "Choisir un fichier", string filter = "Tous les fichiers (*.*)|*.*")
    {
        var dialog = new OpenFileDialog { Title = title, Filter = filter, CheckFileExists = true };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    public string? PickFolder(string title = "Choisir un dossier")
    {
        var dialog = new OpenFolderDialog { Title = title };
        return dialog.ShowDialog() == true ? dialog.FolderName : null;
    }
}
