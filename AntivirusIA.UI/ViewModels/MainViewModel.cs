using System.Collections.ObjectModel;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;

namespace AntivirusIA.UI.ViewModels;

/// <summary>ViewModel racine : navigation latérale, état global affiché dans la barre de titre et bascule de thème.</summary>
public sealed partial class MainViewModel : ObservableObject
{
    private readonly AppSettings _settings;
    private readonly ThemeService _theme;
    private readonly SettingsStore _store;

    public MainViewModel(
        DashboardViewModel dashboard, ScanViewModel scan, QuarantineViewModel quarantine,
        HistoryViewModel history, SettingsViewModel settingsVm,
        AppSettings settings, ThemeService theme, SettingsStore store, ActivityStats stats)
    {
        _settings = settings;
        _theme = theme;
        _store = store;
        Dashboard = dashboard;

        var quarantineItem = new NavItemViewModel("Quarantaine", "Icon.Quarantine", quarantine, "Ctrl+3");
        Items =
        [
            new NavItemViewModel("Tableau de bord", "Icon.Dashboard", dashboard, "Ctrl+1"),
            new NavItemViewModel("Analyse", "Icon.Scan", scan, "Ctrl+2"),
            quarantineItem,
            new NavItemViewModel("Historique", "Icon.History", history, "Ctrl+4"),
            new NavItemViewModel("Réglages", "Icon.Settings", settingsVm, "Ctrl+5"),
        ];
        _current = Items[0];
        _current.IsSelected = true;

        // Pastille de la navigation : nombre de fichiers actuellement en quarantaine
        quarantineItem.Badge = stats.Quarantined;
        stats.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ActivityStats.Quarantined)) quarantineItem.Badge = stats.Quarantined;
        };

        // Le thème peut aussi être changé depuis la page Réglages : la barre latérale suit
        settings.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName != nameof(AppSettings.DarkTheme)) return;
            OnPropertyChanged(nameof(IsDarkTheme));
            OnPropertyChanged(nameof(ThemeName));
        };

        // Les actions rapides du tableau de bord demandent la navigation par message (pas de dépendance circulaire)
        WeakReferenceMessenger.Default.Register<MainViewModel, NavigateMessage>(this, (self, msg) =>
        {
            var target = self.Items.FirstOrDefault(i => i.ViewModel.GetType() == msg.Target);
            if (target is not null) _ = self.NavigateAsync(target);
        });
    }

    public ObservableCollection<NavItemViewModel> Items { get; }

    /// <summary>Exposé pour la pastille d'état de la barre de titre.</summary>
    public DashboardViewModel Dashboard { get; }

    [ObservableProperty] private NavItemViewModel _current;

    public bool IsDarkTheme => _settings.DarkTheme;
    public string ThemeName => _settings.DarkTheme ? "sombre" : "clair";

    [RelayCommand]
    private async Task NavigateAsync(NavItemViewModel? item)
    {
        if (item is null || ReferenceEquals(item, Current)) return;

        Current.IsSelected = false;
        item.IsSelected = true;
        Current = item;

        if (item.ViewModel is IPageViewModel page)
            await page.OnNavigatedToAsync();
    }

    /// <summary>Raccourcis Ctrl+1..5 : le paramètre est l'index (1 à 5) de la page.</summary>
    [RelayCommand]
    private Task GoToAsync(string? index) =>
        int.TryParse(index, out int i) && i >= 1 && i <= Items.Count ? NavigateAsync(Items[i - 1]) : Task.CompletedTask;

    [RelayCommand]
    private void ToggleTheme()
    {
        _settings.DarkTheme = !_settings.DarkTheme;
        _theme.Apply(_settings.DarkTheme);
        _store.Save(_settings);
        OnPropertyChanged(nameof(IsDarkTheme));
        OnPropertyChanged(nameof(ThemeName));
    }
}
