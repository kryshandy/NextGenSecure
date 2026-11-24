using System.Collections.ObjectModel;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusIA.UI.ViewModels;

/// <summary>ViewModel racine : navigation latérale et bascule de thème.</summary>
public sealed partial class MainViewModel : ObservableObject
{
    private readonly AppSettings _settings;
    private readonly ThemeService _theme;
    private readonly SettingsStore _store;

    public MainViewModel(
        DashboardViewModel dashboard, ScanViewModel scan, QuarantineViewModel quarantine,
        HistoryViewModel history, SettingsViewModel settingsVm,
        AppSettings settings, ThemeService theme, SettingsStore store)
    {
        _settings = settings;
        _theme = theme;
        _store = store;

        Items =
        [
            new NavItemViewModel("Tableau de bord", "Icon.Dashboard", dashboard),
            new NavItemViewModel("Analyse", "Icon.Scan", scan),
            new NavItemViewModel("Quarantaine", "Icon.Quarantine", quarantine),
            new NavItemViewModel("Historique", "Icon.History", history),
            new NavItemViewModel("Réglages", "Icon.Settings", settingsVm),
        ];
        _current = Items[0];
        _current.IsSelected = true;
    }

    public ObservableCollection<NavItemViewModel> Items { get; }

    [ObservableProperty] private NavItemViewModel _current;

    public bool IsDarkTheme => _settings.DarkTheme;

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

    [RelayCommand]
    private void ToggleTheme()
    {
        _settings.DarkTheme = !_settings.DarkTheme;
        _theme.Apply(_settings.DarkTheme);
        _store.Save(_settings);
        OnPropertyChanged(nameof(IsDarkTheme));
    }
}
