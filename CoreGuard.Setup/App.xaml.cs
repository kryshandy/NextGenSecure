using System.Windows;

namespace CoreGuard.Setup;

public partial class App : Application
{
    private void OnStartup(object sender, StartupEventArgs e) =>
        new MainWindow(uninstall: e.Args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase)).Show();
}
