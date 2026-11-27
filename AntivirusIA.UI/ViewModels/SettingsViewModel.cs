using System.ComponentModel;
using System.Windows;
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
    private readonly ServiceLink _service;
    private readonly PhishingReviewService _phishing;

    public SettingsViewModel(AppSettings settings, SettingsStore store, ProtectionService protection, ThemeService theme, IDialogService dialogs,
        ServiceLink service, PhishingReviewService phishing)
    {
        _phishing = phishing;
        _phishing.ListsChanged += () => UiThread.Post(RefreshPhishingStatus);
        RefreshPhishingStatus();
        _service = service;
        _service.StatusChanged += () => UiThread.Post(RefreshServiceStatus);
        RefreshServiceStatus();
        Settings = settings;
        _store = store;
        _protection = protection;
        _theme = theme;
        _dialogs = dialogs;

        // Le thème s'applique instantanément ; le reste attend « Appliquer »
        Settings.PropertyChanged += OnSettingsChanged;
        RefreshModelStatus();
        UpdateBands();
    }

    public AppSettings Settings { get; }

    [ObservableProperty] private string _modelStatus = string.Empty;
    [ObservableProperty] private bool _modelFound;
    [ObservableProperty] private string _resolvedModelPath = string.Empty;
    [ObservableProperty] private string _savedMessage = string.Empty;

    // Anti-phishing
    [ObservableProperty] private string _trustedSitesText = string.Empty;
    [ObservableProperty] private bool _hasTrustedSites;
    [ObservableProperty] private string _feedStatus = string.Empty;

    private void RefreshPhishingStatus()
    {
        var sites = PhishingReviewService.TrustedSites();
        HasTrustedSites = sites.Count > 0;
        TrustedSitesText = sites.Count == 0 ? "Aucun site déclaré de confiance."
            : $"{sites.Count} site(s) : " + string.Join(", ", sites.Take(6)) + (sites.Count > 6 ? "…" : "");
        FeedStatus = PhishingReviewService.FeedUpdatedAt is { } at
            ? $"Dernière mise à jour : {at:dd/MM/yyyy HH:mm}."
            : "Instantané livré avec CoreGuard (aucune mise à jour téléchargée).";
    }

    [RelayCommand]
    private void ClearTrustedSites()
    {
        if (!_dialogs.Confirm("Retirer les sites de confiance",
                "Tous les sites seront de nouveau analysés par l'anti-phishing.", "Retirer", danger: true)) return;
        _phishing.ClearTrustedSites();
    }

    [RelayCommand]
    private async Task UpdateFeedNowAsync()
    {
        FeedStatus = "Téléchargement de la liste OpenPhish…";
        FeedStatus = await _phishing.UpdateFeedAsync();
    }

    // Service CoreGuard et auto-défense
    [ObservableProperty] private string _serviceStatus = string.Empty;
    [ObservableProperty] private bool _serviceConnected;
    [ObservableProperty] private string _stopMessage = string.Empty;

    // Paramètres Windows de confidentialité (appliqués immédiatement, pas par « Enregistrer »)
    public bool DenyDesktopCamera
    {
        get => !CoreGuard.Privacy.SensorControl.IsDesktopAppsAccessAllowed("webcam");
        set { CoreGuard.Privacy.SensorControl.SetDesktopAppsAccess("webcam", !value); OnPropertyChanged(); }
    }

    public bool DenyDesktopMicrophone
    {
        get => !CoreGuard.Privacy.SensorControl.IsDesktopAppsAccessAllowed("microphone");
        set { CoreGuard.Privacy.SensorControl.SetDesktopAppsAccess("microphone", !value); OnPropertyChanged(); }
    }

    // Largeurs relatives des trois bandes (Sain / Suspect / Malveillant) de l'aperçu des seuils
    [ObservableProperty] private GridLength _bandHealthy = new(30, GridUnitType.Star);
    [ObservableProperty] private GridLength _bandSuspect = new(40, GridUnitType.Star);
    [ObservableProperty] private GridLength _bandMalicious = new(30, GridUnitType.Star);

    private void UpdateBands()
    {
        int suspect = Settings.ThresholdSuspect;
        int malicious = Settings.ThresholdMalicious;
        BandHealthy = new GridLength(Math.Max(suspect, 1), GridUnitType.Star);
        BandSuspect = new GridLength(Math.Max(malicious - suspect, 1), GridUnitType.Star);
        BandMalicious = new GridLength(Math.Max(100 - malicious, 1), GridUnitType.Star);
    }

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
        else if (e.PropertyName is nameof(AppSettings.ThresholdSuspect) or nameof(AppSettings.ThresholdMalicious))
        {
            UpdateBands();
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

    private void RefreshServiceStatus()
    {
        ServiceConnected = _service.IsConnected;
        var s = _service.Status;
        string selfDefense = _service.SelfDefenseActive ? "active" : "inactive";
        ServiceStatus = s is null
            ? "Service CoreGuard non connecté : protection système inactive (installez-le avec scripts/install-service.ps1)."
            : $"Service connecté (PID {s.ProcessId}). Auto-défense : {selfDefense}. "
              + (s.StopPasswordConfigured ? "Mot de passe de protection configuré." : "Aucun mot de passe : arrêt impossible depuis l'interface.")
              + (s.Modules.FirstOrDefault(m => m.Name == CoreGuard.Ipc.ServiceModules.Amsi) is { } amsi ? $" AMSI : {amsi.Text}." : "")
              + (s.Modules.FirstOrDefault(m => m.Name == CoreGuard.Ipc.ServiceModules.Memory) is { } memory ? $" Mémoire : {memory.Text}." : "")
              + (s.Modules.FirstOrDefault(m => m.Name == CoreGuard.Ipc.ServiceModules.Credentials) is { } creds ? $" Identifiants : {creds.Text}." : "");
        StopProtectionCommand.NotifyCanExecuteChanged();
    }

    private bool CanStopProtection() => _service.IsConnected;

    /// <summary>Arrêt authentifié : le service vérifie le mot de passe par défi-réponse HMAC, puis prévient son watchdog.</summary>
    [RelayCommand(CanExecute = nameof(CanStopProtection))]
    private void StopProtection()
    {
        bool stopped = _dialogs.AskPassword("Désactiver la protection",
            "Le service CoreGuard et son watchdog vont s'arrêter : la protection système sera inactive jusqu'au prochain démarrage du service. "
            + "Saisissez le mot de passe de protection défini à l'installation.",
            "Désactiver", _service.RequestStopAsync);
        StopMessage = stopped ? "Protection arrêtée par mot de passe." : string.Empty;
    }

    [RelayCommand]
    private void ResetThresholds()
    {
        Settings.ThresholdMalicious = 70;
        Settings.ThresholdSuspect = 30;
    }
}
