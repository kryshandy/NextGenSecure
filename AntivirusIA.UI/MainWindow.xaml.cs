using System.Windows;
using AntivirusIA.UI.ViewModels;

namespace AntivirusIA.UI;

public partial class MainWindow : Window
{
    // Résolue par le conteneur DI : le ViewModel est injecté par le constructeur
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        StateChanged += (_, _) => AdaptToState();
    }

    // Avec WindowStyle=None, une fenêtre maximisée déborde d'environ 8 px : on compense par une marge
    private void AdaptToState() =>
        RootGrid.Margin = WindowState == WindowState.Maximized ? new Thickness(8) : new Thickness(0);

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximize(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
