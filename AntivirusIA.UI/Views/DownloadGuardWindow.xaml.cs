using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using CoreGuard.RealTime;

namespace AntivirusIA.UI.Views;

/// <summary>Fenêtre du Smart Download Guard : couleur, origine (marque du Web), signature et raisons.</summary>
public partial class DownloadGuardWindow : Window
{
    private static readonly List<DownloadGuardWindow> Open = [];
    private readonly string _path;
    private readonly Func<Task<string>> _quarantine;

    public DownloadGuardWindow(string path, MarkOfTheWeb? motw, DownloadAssessment assessment, bool alreadyQuarantined, Func<Task<string>> quarantine)
    {
        InitializeComponent();
        _path = path;
        _quarantine = quarantine;

        var (brush, pill, title) = assessment.Level switch
        {
            DownloadLevel.Red => ("DangerBrush", "Pill.Danger", "Téléchargement dangereux"),
            DownloadLevel.Orange => ("WarnBrush", "Pill.Warn", "Téléchargement à vérifier"),
            _ => ("SuccessBrush", "Pill.Success", "Téléchargement vérifié")
        };
        Band.Background = (Brush)FindResource(brush);
        HeaderIcon.Fill = (Brush)FindResource(brush);
        TitleText.Text = title;
        LevelPill.Style = (Style)FindResource(pill);
        LevelPill.Content = assessment.Level switch
        {
            DownloadLevel.Red => "Rouge : ne pas ouvrir",
            DownloadLevel.Orange => "Orange : prudence",
            _ => "Vert : rien d'anormal"
        };
        FileText.Text = Path.GetFileName(path);
        OriginText.Text = motw is null
            ? "Origine inconnue : pas de marque du Web (copie locale, clé USB, archive extraite…)"
            : $"Origine : {(motw.FromInternet ? "Internet" : motw.Zone.ToString())}{(motw.SourceHost is { } h ? $" — {h}" : "")}";
        ReasonsText.Text = string.Join(Environment.NewLine, assessment.Reasons.Select(r => "• " + r));

        if (alreadyQuarantined)
        {
            QuarantineButton.Visibility = Visibility.Collapsed;
            FolderButton.Visibility = Visibility.Collapsed;
            ShowResult("Fichier déjà mis en quarantaine automatiquement (restaurable depuis la page Quarantaine).");
        }
        else if (assessment.Level == DownloadLevel.Green)
        {
            QuarantineButton.Visibility = Visibility.Collapsed;
        }

        // Plusieurs téléchargements à la suite : les fenêtres s'empilent au-dessus des précédentes
        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            double above = Open.Sum(w => w.ActualHeight);
            Left = area.Right - ActualWidth - 8;
            Top = Math.Max(area.Top, area.Bottom - ActualHeight - 8 - above);
            Open.Add(this);
        };
        Closed += (_, _) => Open.Remove(this);
        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed) DragMove(); };
    }

    private void ShowResult(string text)
    {
        ResultText.Text = text;
        ResultText.Visibility = Visibility.Visible;
    }

    private void OnFolder(object sender, RoutedEventArgs e)
    {
        if (File.Exists(_path))
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{_path}\"") { UseShellExecute = false });
    }

    private async void OnQuarantine(object sender, RoutedEventArgs e)
    {
        QuarantineButton.IsEnabled = FolderButton.IsEnabled = false;
        ShowResult(await _quarantine());
        await Task.Delay(2500);
        Close();
    }

    private void OnOk(object sender, RoutedEventArgs e) => Close();
}
