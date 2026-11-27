using System.Windows;
using System.Windows.Controls;
using CoreGuard.Behavior;

namespace AntivirusIA.UI.Views;

/// <summary>Fenêtre « Autoriser / Bloquer » d'une nouvelle persistance. La décision est confiée à l'appelant.</summary>
public partial class PersistencePromptWindow : Window
{
    private readonly Func<Task<string>> _block;
    private readonly Action _allow;
    private bool _decided;

    public PersistencePromptWindow(PersistenceEvent evt, PersistenceAssessment assessment, Action allow, Func<Task<string>> block)
    {
        InitializeComponent();
        _allow = allow;
        _block = block;

        KindText.Text = evt.Kind switch
        {
            "RunKey" => "Lancement automatique (registre Run)",
            "ScheduledTask" => "Tâche planifiée",
            "StartupFolder" => "Fichier du dossier Démarrage",
            "Service" => "Nouveau service Windows",
            _ => evt.Kind
        };
        TargetText.Text = evt.Target;
        CommandText.Text = string.IsNullOrWhiteSpace(evt.Command) ? "(commande non lisible)" : evt.Command;

        var (style, label) = assessment.Level switch
        {
            PersistenceRiskLevel.High => ("Pill.Danger", "Risque élevé"),
            PersistenceRiskLevel.Medium => ("Pill.Warn", "Risque moyen"),
            _ => ("Pill.Success", "Risque faible")
        };
        RiskPill.Style = (Style)FindResource(style);
        RiskPill.Content = label;
        ExplanationText.Text = assessment.Summary;

        // En bas à droite de la zone de travail (au-dessus de la barre des tâches)
        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            Left = area.Right - ActualWidth - 8;
            Top = area.Bottom - ActualHeight - 8;
        };
        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed) DragMove(); };
    }

    /// <summary>Remplace l'explication par celle de l'IA locale (texte brut, jamais interprété).</summary>
    public void SetAiExplanation(string text)
    {
        if (_decided || string.IsNullOrWhiteSpace(text)) return;
        ExplanationTitle.Text = "Explication de l'IA locale";
        ExplanationText.Text = text.Length > 300 ? text[..300] + "…" : text;
    }

    private void OnAllow(object sender, RoutedEventArgs e)
    {
        _decided = true;
        _allow();
        Close();
    }

    private async void OnBlock(object sender, RoutedEventArgs e)
    {
        _decided = true;
        AllowButton.IsEnabled = BlockButton.IsEnabled = false;
        string message = await _block();
        ResultText.Text = message;
        ResultText.Visibility = Visibility.Visible;
        await Task.Delay(2500);
        Close();
    }
}
