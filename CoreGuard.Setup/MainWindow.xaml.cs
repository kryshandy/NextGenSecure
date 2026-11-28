using System.Diagnostics;
using System.Windows;

namespace CoreGuard.Setup;

/// <summary>Assistant : Bienvenue → Mot de passe → Options → Installation (ou désinstallation avec --uninstall).</summary>
public partial class MainWindow : Window
{
    private readonly bool _uninstall;
    private readonly Installer _installer;
    private int _page;
    private bool _done;

    public MainWindow(bool uninstall)
    {
        InitializeComponent();
        _uninstall = uninstall;
        string payload = Path.Combine(AppContext.BaseDirectory, "payload");
        _installer = new Installer(payload, line => Dispatcher.Invoke(() => { LogBox.AppendText(line + Environment.NewLine); LogBox.ScrollToEnd(); }));

        if (_uninstall)
        {
            Heading.Text = "Désinstallation de CoreGuard";
            StepText.Text = "Le service, le fournisseur AMSI, l'hôte de l'extension et les fichiers seront retirés.";
            Show(3);
            UninstallOptions.Visibility = Visibility.Visible;
            NextButton.Content = "Désinstaller";
            return;
        }

        long bytes = _installer.PayloadBytes();
        SizeText.Text = bytes > 0 ? $"Espace nécessaire : {bytes / 1024d / 1024 / 1024:0.0} Go" : "Charge utile introuvable : lancez l'assistant depuis son dossier.";
        NextButton.IsEnabled = bytes > 0;
        bool existing = Installer.ServiceExists && Installer.PasswordConfigured;
        CurrentPanel.Visibility = existing ? Visibility.Visible : Visibility.Collapsed;
        NewPanel.Visibility = existing ? Visibility.Collapsed : Visibility.Visible;
        Show(0);
    }

    private void Show(int page)
    {
        _page = page;
        PageWelcome.Visibility = page == 0 ? Visibility.Visible : Visibility.Collapsed;
        PagePassword.Visibility = page == 1 ? Visibility.Visible : Visibility.Collapsed;
        PageOptions.Visibility = page == 2 ? Visibility.Visible : Visibility.Collapsed;
        PageProgress.Visibility = page == 3 ? Visibility.Visible : Visibility.Collapsed;
        BackButton.Visibility = page is 1 or 2 ? Visibility.Visible : Visibility.Collapsed;
        if (!_uninstall)
        {
            StepText.Text = page switch { 0 => "Étape 1 sur 4 : bienvenue", 1 => "Étape 2 sur 4 : mot de passe de protection", 2 => "Étape 3 sur 4 : options", _ => "Étape 4 sur 4 : installation" };
            NextButton.Content = page == 2 ? "Installer" : "Suivant";
        }
    }

    private void OnKeepChanged(object sender, RoutedEventArgs e) =>
        NewPanel.Visibility = KeepPassword.IsChecked == true ? Visibility.Collapsed : Visibility.Visible;

    private void OnBack(object sender, RoutedEventArgs e) => Show(Math.Max(0, _page - 1));

    private async void OnNext(object sender, RoutedEventArgs e)
    {
        if (_done)
        {
            Close();
            return;
        }
        if (_uninstall) { await RunUninstallAsync(); return; }
        if (_page == 1 && !ValidatePasswords()) return;
        if (_page < 2) { Show(_page + 1); return; }
        await RunInstallAsync();
    }

    private bool ValidatePasswords()
    {
        PasswordError.Text = "";
        bool existing = CurrentPanel.Visibility == Visibility.Visible;
        if (existing && CurrentPassword.Password.Length == 0) { PasswordError.Text = "Saisissez le mot de passe actuel."; return false; }
        if (NewPanel.Visibility == Visibility.Visible)
        {
            if (NewPassword.Password.Length < 8) { PasswordError.Text = "Le mot de passe doit contenir au moins 8 caractères."; return false; }
            if (NewPassword.Password != ConfirmPassword.Password) { PasswordError.Text = "Les deux mots de passe ne correspondent pas."; return false; }
        }
        return true;
    }

    private async Task RunInstallAsync()
    {
        Show(3);
        NextButton.IsEnabled = BackButton.IsEnabled = CloseButton.IsEnabled = false;
        var options = new InstallOptions(
            NewPanel.Visibility == Visibility.Visible ? NewPassword.Password : null,
            CurrentPanel.Visibility == Visibility.Visible ? CurrentPassword.Password : null,
            OptService.IsChecked == true, OptAmsi.IsChecked == true, OptBrowser.IsChecked == true, OptDesktop.IsChecked == true);
        var progress = new Progress<int>(v => Progress.Value = v);
        try
        {
            await Task.Run(() => _installer.Install(options, progress));
            Heading.Text = "CoreGuard est installé";
            StepText.Text = "La protection est active. CoreGuard va s'ouvrir.";
            NextButton.Content = "Terminer";
            _done = true;
            // Lancé par l'Explorateur : l'application ne doit pas hériter des droits administrateur de l'installateur
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{Installer.AppExe}\"") { UseShellExecute = false });
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            LogBox.AppendText(Environment.NewLine + "ÉCHEC : " + ex.Message + Environment.NewLine);
            StepText.Text = "L'installation n'a pas abouti : voir le journal.";
            NextButton.Content = "Fermer";
            _done = true;
        }
        finally
        {
            NextButton.IsEnabled = CloseButton.IsEnabled = true;
        }
    }

    private async Task RunUninstallAsync()
    {
        NextButton.IsEnabled = CloseButton.IsEnabled = false;
        string? password = UninstallPassword.Password.Length > 0 ? UninstallPassword.Password : null;
        bool removeData = RemoveData.IsChecked == true;
        var progress = new Progress<int>(v => Progress.Value = v);
        try
        {
            await Task.Run(() => _installer.Uninstall(password, removeData, progress));
            StepText.Text = "CoreGuard a été désinstallé.";
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            LogBox.AppendText(Environment.NewLine + "ÉCHEC : " + ex.Message + Environment.NewLine);
            StepText.Text = "La désinstallation n'a pas abouti : voir le journal.";
        }
        NextButton.Content = "Fermer";
        _done = true;
        NextButton.IsEnabled = CloseButton.IsEnabled = true;
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
