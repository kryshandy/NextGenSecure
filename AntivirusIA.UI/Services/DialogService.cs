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

    /// <summary>Demande un mot de passe et le soumet ; vrai si <paramref name="submit"/> l'a accepté.</summary>
    bool AskPassword(string title, string message, string confirmText, Func<string, Task<CoreGuard.Ipc.StopResult>> submit);
}

public sealed class DialogService : IDialogService
{
    public bool Confirm(string title, string message, string confirmText = "Confirmer", bool danger = false)
    {
        var dialog = new ConfirmDialog(title, message, confirmText, danger) { Owner = VisibleOwner() };
        return dialog.ShowDialog() == true;
    }

    // Fenêtre principale cachée (mode arrière-plan) : pas de propriétaire, la boîte s'affiche seule au premier plan
    private static Window? VisibleOwner() =>
        Application.Current.MainWindow is { IsVisible: true } w ? w : null;

    public string? PickFile(string title = "Choisir un fichier", string filter = "Tous les fichiers (*.*)|*.*")
    {
        var dialog = new OpenFileDialog { Title = title, Filter = filter, CheckFileExists = true };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    public bool AskPassword(string title, string message, string confirmText, Func<string, Task<CoreGuard.Ipc.StopResult>> submit)
    {
        var dialog = new PasswordDialog(title, message, confirmText, submit) { Owner = VisibleOwner() };
        return dialog.ShowDialog() == true;
    }

    public string? PickFolder(string title = "Choisir un dossier")
    {
        var dialog = new OpenFolderDialog { Title = title };
        return dialog.ShowDialog() == true ? dialog.FolderName : null;
    }
}
