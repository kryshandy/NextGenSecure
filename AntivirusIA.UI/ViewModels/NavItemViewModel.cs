using System.Windows;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AntivirusIA.UI.ViewModels;

/// <summary>Page navigable : rafraîchie à chaque affichage.</summary>
public interface IPageViewModel
{
    Task OnNavigatedToAsync();
}

/// <summary>Demande de navigation émise par une page (actions rapides) et traitée par <see cref="MainViewModel"/>.</summary>
public sealed record NavigateMessage(Type Target);

/// <summary>Entrée de la navigation latérale.</summary>
public sealed partial class NavItemViewModel(string title, string iconKey, object viewModel, string shortcut = "") : ObservableObject
{
    public string Title { get; } = title;
    public object ViewModel { get; } = viewModel;

    /// <summary>Raccourci clavier affiché dans l'infobulle (ex. « Ctrl+2 »).</summary>
    public string ToolTipText { get; } = string.IsNullOrEmpty(shortcut) ? title : $"{title} ({shortcut})";

    // Icône vectorielle résolue depuis Themes/Icons.xaml
    public Geometry? Icon { get; } = Application.Current?.TryFindResource(iconKey) as Geometry;

    [ObservableProperty] private bool _isSelected;

    /// <summary>Compteur affiché en pastille (0 = masquée).</summary>
    [ObservableProperty] private int _badge;
}
