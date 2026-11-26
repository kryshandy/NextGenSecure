using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using CoreGuard.Ipc;

namespace AntivirusIA.UI.Views;

/// <summary>
/// Écran de verrouillage d'urgence : plein écran sur l'ensemble des moniteurs, au premier plan, réactivé dès
/// qu'il perd le focus, fermeture refusée tant que le service n'a pas validé le mot de passe de protection.
/// </summary>
public partial class LockScreenWindow : Window
{
    private readonly Func<string, Task<StopResult>> _unlock;
    private readonly DispatcherTimer _keepOnTop;
    private bool _released;

    public LockScreenWindow(string reason, Func<string, Task<StopResult>> unlock)
    {
        InitializeComponent();
        _unlock = unlock;
        ReasonText.Text = "Motif : " + reason;

        Left = SystemParameters.VirtualScreenLeft;
        Top = SystemParameters.VirtualScreenTop;
        Width = SystemParameters.VirtualScreenWidth;
        Height = SystemParameters.VirtualScreenHeight;

        Loaded += (_, _) => { Activate(); Password.Focus(); };
        Deactivated += (_, _) => Reclaim();
        Closing += (_, e) => e.Cancel = !_released;

        // Une autre fenêtre « toujours au premier plan » ne doit pas pouvoir recouvrir l'écran de verrouillage
        _keepOnTop = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
        _keepOnTop.Tick += (_, _) => Reclaim();
        _keepOnTop.Start();
    }

    public IntPtr Handle => new WindowInteropHelper(this).Handle;

    private void Reclaim()
    {
        if (_released) return;
        Topmost = false;
        Topmost = true;
        Activate();
        Password.Focus();
    }

    /// <summary>Fermeture autorisée (verrouillage levé par le service).</summary>
    public void Release()
    {
        _released = true;
        _keepOnTop.Stop();
        Close();
    }

    private void OnPasswordKey(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) OnUnlock(sender, e);
    }

    private async void OnUnlock(object sender, RoutedEventArgs e)
    {
        string password = Password.Password;
        Password.Clear();
        if (password.Length == 0) return;

        UnlockButton.IsEnabled = false;
        ErrorText.Visibility = Visibility.Collapsed;
        StopResult result;
        try
        {
            result = await _unlock(password);
        }
        finally
        {
            UnlockButton.IsEnabled = true;
        }

        if (!result.Accepted)
        {
            ErrorText.Text = result.Message;
            ErrorText.Visibility = Visibility.Visible;
            Password.Focus();
        }
        // En cas de succès, le service publie son nouvel état et le contrôleur ferme la fenêtre
    }
}
