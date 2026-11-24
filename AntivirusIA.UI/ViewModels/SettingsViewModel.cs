using System.ComponentModel;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

public sealed partial class SettingsViewModel : ObservableObject, IPageViewModel
{
    private readonly SettingsStore _store;
    private readonly ProtectionService _protection;
    private readonly ThemeService _theme;
    private readonly IDialogService _dialogs;

    public SettingsViewModel(AppSettings settings, SettingsStore store, ProtectionService protection, ThemeService theme, IDialogService dialogs)
    {
        Settings = settings;
        _store = store;
        _protection = protection;
        _theme = theme;
        _dialogs = dialogs;

        // Le thème s'applique instantanément ; le reste attend « Appliquer »
        Settings.PropertyChanged += OnSettingsChanged;
        RefreshModelStatus();
    }

    public AppSettings Settings { get; }

    [ObservableProperty] private string _modelStatus = string.Empty;
    [ObservableProperty] private bool _modelFound;
    [ObservableProperty] private string _resolvedModelPath = string.Empty;
    [ObservableProperty] private string _savedMessage = string.Empty;

    private void OnSettingsChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AppSettings.DarkTheme))
        {
            _theme.Apply(Settings.DarkTheme);
            _store.Save(Settings);
        }
        else if (e.PropertyName == nameof(AppSettings.ModelPath))
        {
            RefreshModelStatus();
        }
        SavedMessage = string.Empty;
    }

    public Task OnNavigatedToAsync()
    {
        RefreshModelStatus();
        return Task.CompletedTask;
    }

    private void RefreshModelStatus()
    {
        ResolvedModelPath = ModelLocator.Resolve(Settings.ModelPath);
        ModelFound = File.Exists(ResolvedModelPath);
        ModelStatus = ModelFound
            ? "Modèle trouvé. Un changement de chemin est pris en compte au prochain démarrage."
            : "Modèle introuvable : les analyses utiliseront uniquement les moteurs locaux.";
    }

    [RelayCommand]
    private void BrowseModel()
    {
        string? path = _dialogs.PickFile("Choisir le modèle GGUF", "Modèle GGUF (*.gguf)|*.gguf|Tous les fichiers (*.*)|*.*");
        if (path is not null) Settings.ModelPath = path;
    }

    [RelayCommand]
    private async Task ApplyAsync()
    {
        _store.Save(Settings);
        await _protection.ApplyAsync();
        SavedMessage = "Réglages enregistrés et appliqués.";
    }

    [RelayCommand]
    private void ResetThresholds()
    {
        Settings.ThresholdMalicious = 70;
        Settings.ThresholdSuspect = 30;
    }
}
