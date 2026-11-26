using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using CoreGuard.Ipc;

namespace AntivirusIA.UI.Views;

/// <summary>
/// Écran de verrouillage d'urgence : plein écran sur l'ensemble des moniteurs, au premier plan, réactivé dès
/// qu'il perd le focus, fermeture refusée tant que le service n'a pas validé le mot de passe de protection.
/// La saisie du mot de passe s'affiche avec Ctrl+R (masquée par Échap ou après 60 s sans tentative) ; le mot de
/// passe reste obligatoire : le raccourci ne fait que révéler le champ.
/// </summary>
public partial class LockScreenWindow : Window
{
    private static readonly TimeSpan PanelTimeout = TimeSpan.FromSeconds(60);

    private readonly Func<string, Task<StopResult>> _unlock;
    private readonly DispatcherTimer _keepOnTop;
    private readonly DispatcherTimer _hidePanel;
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

        Loaded += (_, _) => { Activate(); Focus(); };
        Deactivated += (_, _) => Reclaim();
        Closing += (_, e) => e.Cancel = !_released;
        PreviewKeyDown += OnPreviewKey;

        // Une autre fenêtre « toujours au premier plan » ne doit pas pouvoir recouvrir l'écran de verrouillage
        _keepOnTop = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
        _keepOnTop.Tick += (_, _) => Reclaim();
        _keepOnTop.Start();

        _hidePanel = new DispatcherTimer { Interval = PanelTimeout };
        _hidePanel.Tick += (_, _) => HidePanel();
    }

    public IntPtr Handle => new WindowInteropHelper(this).Handle;

    /// <summary>Raccourci qui révèle la saisie du mot de passe (logique pure).</summary>
    public static bool IsRevealShortcut(Key key, ModifierKeys modifiers) =>
        key == Key.R && (modifiers & ModifierKeys.Control) != 0 && (modifiers & (ModifierKeys.Alt | ModifierKeys.Windows)) == 0;

    private void OnPreviewKey(object sender, KeyEventArgs e)
    {
        if (IsRevealShortcut(e.Key, Keyboard.Modifiers))
        {
            ShowPanel();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && UnlockPanel.Visibility == Visibility.Visible)
        {
            HidePanel();
            e.Handled = true;
        }
    }

    private void ShowPanel()
    {
        UnlockPanel.Visibility = Visibility.Visible;
        HintText.Visibility = Visibility.Collapsed;
        Password.Focus();
        RestartHideTimer();
    }

    private void HidePanel()
    {
        _hidePanel.Stop();
        Password.Clear();
        ErrorText.Visibility = Visibility.Collapsed;
        UnlockPanel.Visibility = Visibility.Collapsed;
        HintText.Visibility = Visibility.Visible;
        Focus();
    }

    private void RestartHideTimer()
    {
        _hidePanel.Stop();
        _hidePanel.Start();
    }

    private void Reclaim()
    {
        if (_released) return;
        Topmost = false;
        Topmost = true;
        Activate();
        if (UnlockPanel.Visibility == Visibility.Visible) Password.Focus();
        else Focus();
    }

    /// <summary>Fermeture autorisée (verrouillage levé par le service).</summary>
    public void Release()
    {
        _released = true;
        _keepOnTop.Stop();
        _hidePanel.Stop();
        Close();
    }

    private void OnPasswordKey(object sender, KeyEventArgs e)
    {
        RestartHideTimer();
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
            RestartHideTimer();
        }
        // En cas de succès, le service publie son nouvel état et le contrôleur ferme la fenêtre
    }
}
