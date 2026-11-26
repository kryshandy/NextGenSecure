using System.Collections.ObjectModel;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CoreGuard.Vault;

namespace AntivirusIA.UI.ViewModels;

public enum VaultState { NeedsCreation, Locked, Unlocked }

/// <summary>
/// Page « Coffre-fort ». Les mots de passe (maître et entrées) arrivent par les PasswordBox de la vue, en
/// paramètre des méthodes : ils ne sont jamais stockés dans une propriété liée de l'interface.
/// </summary>
public sealed partial class VaultViewModel : ObservableObject, IPageViewModel
{
    private readonly VaultService _vault;
    private readonly IDialogService _dialogs;

    public VaultViewModel(VaultService vault, IDialogService dialogs)
    {
        _vault = vault;
        _dialogs = dialogs;
        _vault.StateChanged += () => UiThread.Post(() => _ = RefreshAsync());
        RefreshState();
    }

    public ObservableCollection<CredentialEntry> Entries { get; } = [];

    [ObservableProperty] private VaultState _state;
    [ObservableProperty] private string _message = string.Empty;
    [ObservableProperty] private bool _busy;

    // Formulaire d'ajout (hors mot de passe)
    [ObservableProperty] private string _newTitle = string.Empty;
    [ObservableProperty] private string _newUrl = "https://";
    [ObservableProperty] private string _newUsername = string.Empty;

    public string AutoLockText => $"Verrouillage automatique après {VaultService.AutoLock.TotalMinutes} min d'inactivité.";

    public Task OnNavigatedToAsync() => RefreshAsync();

    private void RefreshState() =>
        State = !_vault.Exists ? VaultState.NeedsCreation : _vault.IsUnlocked ? VaultState.Unlocked : VaultState.Locked;

    private async Task RefreshAsync()
    {
        RefreshState();
        Entries.Clear();
        if (State != VaultState.Unlocked) return;
        foreach (var e in (await _vault.ListAsync()).OrderBy(e => e.Title, StringComparer.CurrentCultureIgnoreCase)) Entries.Add(e);
    }

    public async Task CreateAsync(string master, string confirmation)
    {
        if (master.Length < 12) { Message = "Mot de passe maître : 12 caractères minimum."; return; }
        if (master != confirmation) { Message = "Les deux saisies ne correspondent pas."; return; }
        Busy = true;
        try
        {
            await _vault.CreateAsync(master);
            Message = "Coffre créé et déverrouillé. Retenez bien ce mot de passe : il n'existe aucun moyen de le récupérer.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException)
        {
            Message = "Création impossible : " + ex.Message;
        }
        finally { Busy = false; }
        await RefreshAsync();
    }

    public async Task UnlockAsync(string master)
    {
        Busy = true;
        try
        {
            Message = await _vault.UnlockAsync(master) ? string.Empty : "Mot de passe maître incorrect.";
        }
        finally { Busy = false; }
        await RefreshAsync();
    }

    public async Task<bool> AddAsync(string password)
    {
        if (string.IsNullOrWhiteSpace(NewTitle) || string.IsNullOrWhiteSpace(NewUsername) || string.IsNullOrEmpty(password))
        {
            Message = "Titre, identifiant et mot de passe sont requis.";
            return false;
        }
        if (!Uri.TryCreate(NewUrl.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            Message = "Adresse du site : une URL https:// complète est requise (l'auto-remplissage n'agit que sur ce site).";
            return false;
        }
        await _vault.AddAsync(NewTitle.Trim(), NewUsername.Trim(), uri.GetLeftPart(UriPartial.Authority), password);
        Message = $"« {NewTitle.Trim()} » ajouté.";
        NewTitle = string.Empty;
        NewUrl = "https://";
        NewUsername = string.Empty;
        await RefreshAsync();
        return true;
    }

    public static string Generate() => VaultService.GeneratePassword();

    [RelayCommand]
    private async Task DeleteAsync(CredentialEntry? entry)
    {
        if (entry is null) return;
        if (!_dialogs.Confirm("Supprimer l'identifiant", $"Supprimer « {entry.Title} » ({entry.Username}) du coffre ? Cette action est définitive.", "Supprimer", danger: true))
            return;
        await _vault.DeleteAsync(entry.Id);
        Message = $"« {entry.Title} » supprimé.";
        await RefreshAsync();
    }

    [RelayCommand]
    private void Lock()
    {
        _vault.Lock();
        Message = "Coffre verrouillé.";
    }
}
