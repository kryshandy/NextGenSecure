using System.Windows;
using CoreGuard.Ipc;

namespace AntivirusIA.UI.Views;

/// <summary>
/// Demande le mot de passe de protection et transmet la tentative à <c>submit</c> (défi-réponse avec le service).
/// Le dialogue reste ouvert et affiche le refus tant que le service n'a pas accepté.
/// </summary>
public partial class PasswordDialog : Window
{
    private readonly Func<string, Task<StopResult>> _submit;

    public PasswordDialog(string title, string message, string confirmText, Func<string, Task<StopResult>> submit)
    {
        InitializeComponent();
        _submit = submit;
        TitleText.Text = title;
        MessageText.Text = message;
        ConfirmButton.Content = confirmText;
        Loaded += (_, _) => Password.Focus();
        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed) DragMove(); };
    }

    public StopResult? Result { get; private set; }

    private async void OnConfirm(object sender, RoutedEventArgs e)
    {
        if (Password.Password.Length == 0) { ShowError("Saisissez le mot de passe."); return; }

        SetBusy(true);
        StopResult result;
        try
        {
            result = await _submit(Password.Password);
        }
        finally
        {
            Password.Clear();
            SetBusy(false);
        }

        if (result.Accepted)
        {
            Result = result;
            DialogResult = true;
        }
        else
        {
            ShowError(result.Message);
            Password.Focus();
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

    private void SetBusy(bool busy)
    {
        Password.IsEnabled = !busy;
        ConfirmButton.IsEnabled = !busy;
        CancelButton.IsEnabled = !busy;
        if (busy) ErrorText.Visibility = Visibility.Collapsed;
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
