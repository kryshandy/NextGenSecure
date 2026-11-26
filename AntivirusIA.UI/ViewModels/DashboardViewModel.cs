using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;

namespace AntivirusIA.UI.ViewModels;

public enum ProtectionLevel { Protected, Attention, Danger }

/// <summary>Filtre du flux d'alertes.</summary>
public enum AlertFilterKind { All, Critical, Warning, Info }

public sealed partial class DashboardViewModel : ObservableObject, IPageViewModel
{
    // Fenêtre pendant laquelle une alerte influe sur le statut global
    private static readonly TimeSpan RecentWindow = TimeSpan.FromMinutes(10);

    private readonly AlertHub _hub;
    private readonly ProtectionService _protection;
    private readonly ScanViewModel _scan;
    private readonly IDialogService _dialogs;
    private readonly DispatcherTimer _refreshTimer;

    public DashboardViewModel(ActivityStats stats, AlertHub hub, ProtectionService protection,
        AppSettings settings, SettingsStore store, ScanViewModel scan, IDialogService dialogs)
    {
        Stats = stats;
        _hub = hub;
        _protection = protection;
        _scan = scan;
        _dialogs = dialogs;

        // Un interrupteur par module : il écrit le réglage, l'enregistre, puis ré-applique la protection
        void Apply() { store.Save(settings); _ = protection.ApplyAsync(); }
        Modules =
        [
            new(protection.Files, "Icon.Download", () => settings.MonitorDownloads, v => { settings.MonitorDownloads = v; Apply(); }),
            new(protection.Canaries, "Icon.Bug", () => settings.CanariesEnabled, v => { settings.CanariesEnabled = v; Apply(); }),
            new(protection.Behavior, "Icon.Bolt", () => settings.BehaviorEnabled, v => { settings.BehaviorEnabled = v; Apply(); }),
            new(protection.Persistence, "Icon.Key", () => settings.PersistenceEnabled, v => { settings.PersistenceEnabled = v; Apply(); }),
            new(protection.Network, "Icon.Globe", null, null),
            new(protection.Clipboard, "Icon.Clipboard", () => settings.ClipboardEnabled, v => { settings.ClipboardEnabled = v; Apply(); }),
            new(protection.Sensors, "Icon.Camera", () => settings.SensorsEnabled, v => { settings.SensorsEnabled = v; Apply(); }),
            new(protection.BadUsb, "Icon.Keyboard", () => settings.BadUsbEnabled, v => { settings.BadUsbEnabled = v; Apply(); }),
            new(protection.Paranoia, "Icon.Lock", () => settings.ParanoiaEnabled, v => { settings.ParanoiaEnabled = v; Apply(); }),
        ];

        // Si un réglage change depuis la page Réglages, les interrupteurs se resynchronisent
        settings.PropertyChanged += (_, _) => { foreach (var m in Modules) m.RefreshSetting(); };

        // Vue privée du flux, filtrable par sévérité
        AlertsView = new ListCollectionView(_hub.Alerts);
        AlertsView.Filter = o => o is AlertItem a && MatchesFilter(a);
        _hub.Alerts.CollectionChanged += (_, _) => UpdateAlertCounts();

        _hub.Published += _ =>
        {
            Stats.AlertCount++;
            RefreshStatus();
        };
        _protection.ModulesChanged += RefreshStatus;

        // Réévalue périodiquement : une alerte ancienne cesse de dégrader le statut
        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _refreshTimer.Tick += (_, _) => RefreshStatus();
        _refreshTimer.Start();
        RefreshStatus();
        UpdateAlertCounts();
    }

    public ActivityStats Stats { get; }
    public ObservableCollection<AlertItem> Alerts => _hub.Alerts;
    public ICollectionView AlertsView { get; }
    public ObservableCollection<ModuleCardViewModel> Modules { get; }

    [ObservableProperty] private ProtectionLevel _level = ProtectionLevel.Protected;
    [ObservableProperty] private string _statusTitle = "Votre appareil est protégé";
    [ObservableProperty] private string _statusSubtitle = string.Empty;
    [ObservableProperty] private string _statusShort = "Protégé";
    [ObservableProperty] private string _modulesText = string.Empty;

    /// <summary>Score de protection de 0 à 100 (affiché au centre de l'anneau).</summary>
    [ObservableProperty] private int _protectionScore = 100;

    [ObservableProperty] private AlertFilterKind _alertFilter = AlertFilterKind.All;
    [ObservableProperty] private int _filteredAlertCount;
    [ObservableProperty] private string _alertsEmptyText = "Aucune alerte : tout est calme.";

    partial void OnAlertFilterChanged(AlertFilterKind value)
    {
        AlertsView.Refresh();
        UpdateAlertCounts();
    }

    public Task OnNavigatedToAsync()
    {
        RefreshStatus();
        return Task.CompletedTask;
    }

    private bool MatchesFilter(AlertItem a) => AlertFilter switch
    {
        AlertFilterKind.Critical => a.Severity == AlertSeverity.Critical,
        AlertFilterKind.Warning => a.Severity == AlertSeverity.Warning,
        AlertFilterKind.Info => a.Severity == AlertSeverity.Info,
        _ => true
    };

    private void UpdateAlertCounts()
    {
        FilteredAlertCount = _hub.Alerts.Count(MatchesFilter);
        AlertsEmptyText = _hub.Alerts.Count == 0
            ? "Aucune alerte : tout est calme. Les événements de protection apparaîtront ici en temps réel."
            : "Aucune alerte ne correspond à ce filtre.";
    }

    private void RefreshStatus()
    {
        var since = DateTime.Now - RecentWindow;
        var recent = _hub.Alerts.Where(a => a.WhenLocal >= since).ToList();
        int critical = recent.Count(a => a.Severity == AlertSeverity.Critical);
        int warnings = recent.Count(a => a.Severity == AlertSeverity.Warning);
        int unavailable = _protection.Modules.Count(m => m.State == ModuleState.Unavailable);
        int disabled = _protection.Modules.Count(m => m.State == ModuleState.Disabled);
        int active = _protection.ActiveCount;

        ModulesText = $"{active} / {_protection.Modules.Count} modules actifs";

        // Score : on retranche des points pour les modules coupés ou indisponibles et pour les alertes récentes
        int score = 100 - disabled * 4 - unavailable * 12 - Math.Min(warnings * 8, 24) - Math.Min(critical * 30, 60);
        ProtectionScore = Math.Clamp(score, 5, 100);

        if (critical > 0)
        {
            Level = ProtectionLevel.Danger;
            StatusTitle = "Menace détectée";
            StatusShort = "Menace détectée";
            StatusSubtitle = $"{critical} alerte(s) critique(s) ces 10 dernières minutes. Consultez le flux d'alertes.";
        }
        else if (warnings > 0 || unavailable > 0)
        {
            Level = ProtectionLevel.Attention;
            StatusTitle = "Attention requise";
            StatusShort = "Attention requise";
            StatusSubtitle = warnings > 0
                ? $"{warnings} avertissement(s) récent(s)."
                : $"{unavailable} module(s) indisponible(s) : certaines protections sont limitées.";
        }
        else
        {
            Level = ProtectionLevel.Protected;
            StatusTitle = "Votre appareil est protégé";
            StatusShort = "Protégé";
            StatusSubtitle = "Aucune menace active. La protection temps réel est en veille attentive.";
        }
    }

    /// <summary>Analyse rapide : dossier Téléchargements (point d'entrée n°1 des menaces), à défaut Documents.</summary>
    [RelayCommand]
    private async Task QuickScanAsync()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string path = Path.Combine(profile, "Downloads");
        if (!Directory.Exists(path))
            path = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        WeakReferenceMessenger.Default.Send(new NavigateMessage(typeof(ScanViewModel)));
        await _scan.ScanPathAsync(path);
    }

    [RelayCommand]
    private async Task ScanFolderAsync()
    {
        string? path = _dialogs.PickFolder("Choisir un dossier à analyser");
        if (path is null) return;

        WeakReferenceMessenger.Default.Send(new NavigateMessage(typeof(ScanViewModel)));
        await _scan.ScanPathAsync(path);
    }

    /// <summary>Démonstration : injecte une alerte factice, clairement libellée comme simulation.</summary>
    [RelayCommand]
    private void SimulateAlert()
    {
        _hub.Publish(AlertSeverity.Critical, "Simulation", "Alerte de démonstration (simulation)",
            "Un comportement de type ransomware a été simulé pour illustrer le flux temps réel.");
    }

    [RelayCommand]
    private void ClearAlerts()
    {
        _hub.Alerts.Clear();
        RefreshStatus();
    }
}
