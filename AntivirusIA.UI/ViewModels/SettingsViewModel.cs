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
        PairPhoneCommand.NotifyCanExecuteChanged();
        RevokePhoneCommand.NotifyCanExecuteChanged();
        RefreshRemoteStatus();
    }

    private bool CanStopProtection() => _service.IsConnected;

    // ---- Contrôle à distance par téléphone ----
    [ObservableProperty] private string _remoteStatus = string.Empty;
    [ObservableProperty] private System.Windows.Media.ImageSource? _remoteQr;
    [ObservableProperty] private string _remoteUrls = string.Empty;
    [ObservableProperty] private bool _remoteQrVisible;

    private void RefreshRemoteStatus() =>
        RemoteStatus = !_service.IsConnected ? "Service CoreGuard non connecté : le contrôle à distance est assuré par le service."
            : _service.RemoteText ?? "Service à mettre à jour (scripts/install-service.ps1) pour le contrôle à distance.";

    /// <summary>
    /// Associe un téléphone : le service crée une clé de 256 bits et renvoie les adresses ; le QR code contient l'adresse
    /// et la clé (après « # », jamais envoyée sur le réseau). Toute association précédente est révoquée.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanStopProtection))]
    private void PairPhone()
    {
        CoreGuard.Ipc.RemotePairing? pairing = null;
        bool ok = _dialogs.AskPassword("Associer un téléphone",
            "Le téléphone associé pourra verrouiller ou déverrouiller ce PC et activer ou désactiver le Mode Paranoïa, depuis le même Wi-Fi " +
            "ou le point d'accès mobile du PC (sans Internet). Saisissez le mot de passe de protection pour afficher le QR code.",
            "Associer", async pwd =>
            {
                pairing = await _service.RemoteAsync(pair: true, pwd);
                return new CoreGuard.Ipc.StopResult(pairing.Enabled, pairing.Message);
            });
        if (!ok || pairing is not { Enabled: true } p || p.Urls.Count == 0)
        {
            RemoteQrVisible = false;
            RemoteStatus = pairing?.Message ?? RemoteStatus;
            return;
        }
        RemoteQr = QrImage(p.Urls[0]);
        RemoteUrls = "Adresse(s) : " + string.Join("   ou   ", p.Urls.Select(u => u[..u.IndexOf('#')]));
        RemoteQrVisible = true;
        RemoteStatus = "Scannez le QR code avec l'appareil photo du téléphone (connecté au même Wi-Fi ou au point d'accès du PC).";
    }

    [RelayCommand(CanExecute = nameof(CanStopProtection))]
    private void RevokePhone()
    {
        CoreGuard.Ipc.RemotePairing? result = null;
        bool ok = _dialogs.AskPassword("Révoquer le téléphone",
            "Le téléphone associé ne pourra plus agir sur ce PC.", "Révoquer", async pwd =>
            {
                result = await _service.RemoteAsync(pair: false, pwd);
                return new CoreGuard.Ipc.StopResult(!result.Enabled && result.Message.Contains("désactivé"), result.Message);
            });
        if (ok) { RemoteQrVisible = false; RemoteQr = null; RemoteUrls = string.Empty; RemoteStatus = result?.Message ?? RemoteStatus; }
    }

    [RelayCommand]
    private static void OpenHotspotSettings() =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ms-settings:network-mobilehotspot") { UseShellExecute = true });

    private static System.Windows.Media.ImageSource QrImage(string text)
    {
        var writer = new ZXing.BarcodeWriterPixelData
        {
            Format = ZXing.BarcodeFormat.QR_CODE,
            Options = new ZXing.QrCode.QrCodeEncodingOptions { Width = 260, Height = 260, Margin = 1 }
        };
        var data = writer.Write(text);
        var bitmap = System.Windows.Media.Imaging.BitmapSource.Create(data.Width, data.Height, 96, 96,
            System.Windows.Media.PixelFormats.Bgra32, null, data.Pixels, data.Width * 4);
        bitmap.Freeze();
        return bitmap;
    }

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
