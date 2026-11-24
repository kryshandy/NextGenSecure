using System.Windows;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AntivirusIA.UI.ViewModels;

/// <summary>Page navigable : rafraîchie à chaque affichage.</summary>
public interface IPageViewModel
{
    Task OnNavigatedToAsync();
}

/// <summary>Entrée de la navigation latérale.</summary>
public sealed partial class NavItemViewModel(string title, string iconKey, object viewModel) : ObservableObject
{
    public string Title { get; } = title;
    public object ViewModel { get; } = viewModel;

    // Icône vectorielle résolue depuis Themes/Icons.xaml
    public Geometry? Icon { get; } = Application.Current?.TryFindResource(iconKey) as Geometry;

    [ObservableProperty] private bool _isSelected;
}
