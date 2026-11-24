using System.Collections.ObjectModel;
using System.Windows.Threading;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

public enum ProtectionLevel { Protected, Attention, Danger }

public sealed partial class DashboardViewModel : ObservableObject, IPageViewModel
{
    // Fenêtre pendant laquelle une alerte influe sur le statut global
    private static readonly TimeSpan RecentWindow = TimeSpan.FromMinutes(10);

    private readonly AlertHub _hub;
    private readonly ProtectionService _protection;
    private readonly DispatcherTimer _refreshTimer;

    public DashboardViewModel(ActivityStats stats, AlertHub hub, ProtectionService protection)
    {
        Stats = stats;
        _hub = hub;
        _protection = protection;

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
    }

    public ActivityStats Stats { get; }
    public ObservableCollection<AlertItem> Alerts => _hub.Alerts;
    public ObservableCollection<ProtectionModule> Modules => _protection.Modules;

    [ObservableProperty] private ProtectionLevel _level = ProtectionLevel.Protected;
    [ObservableProperty] private string _statusTitle = "Votre appareil est protégé";
    [ObservableProperty] private string _statusSubtitle = string.Empty;
    [ObservableProperty] private string _modulesText = string.Empty;

    public Task OnNavigatedToAsync()
    {
        RefreshStatus();
        return Task.CompletedTask;
    }

    private void RefreshStatus()
    {
        var since = DateTime.Now - RecentWindow;
        var recent = _hub.Alerts.Where(a => a.WhenLocal >= since).ToList();
        int critical = recent.Count(a => a.Severity == AlertSeverity.Critical);
        int warnings = recent.Count(a => a.Severity == AlertSeverity.Warning);
        int unavailable = _protection.Modules.Count(m => m.State == ModuleState.Unavailable);
        int active = _protection.ActiveCount;

        ModulesText = $"{active} / {_protection.Modules.Count} modules actifs";

        if (critical > 0)
        {
            Level = ProtectionLevel.Danger;
            StatusTitle = "Menace détectée";
            StatusSubtitle = $"{critical} alerte(s) critique(s) ces 10 dernières minutes. Consultez le flux d'alertes.";
        }
        else if (warnings > 0 || unavailable > 0)
        {
            Level = ProtectionLevel.Attention;
            StatusTitle = "Attention requise";
            StatusSubtitle = warnings > 0
                ? $"{warnings} avertissement(s) récent(s)."
                : $"{unavailable} module(s) indisponible(s) : certaines protections sont limitées.";
        }
        else
        {
            Level = ProtectionLevel.Protected;
            StatusTitle = "Votre appareil est protégé";
            StatusSubtitle = "Aucune menace active. La protection temps réel est en veille attentive.";
        }
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
