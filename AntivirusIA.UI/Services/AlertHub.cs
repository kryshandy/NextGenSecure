using System.Collections.ObjectModel;
using AntivirusIA.UI.Models;

namespace AntivirusIA.UI.Services;

/// <summary>
/// Bus d'alertes unique : toute source (canaris, comportement, scan...) publie ici, depuis n'importe quel thread.
/// La collection n'est modifiée que sur le thread UI.
/// </summary>
public sealed class AlertHub
{
    private const int MaxAlerts = 200;

    public ObservableCollection<AlertItem> Alerts { get; } = new();

    /// <summary>Levé sur le thread UI après insertion d'une alerte.</summary>
    public event Action<AlertItem>? Published;

    public void Publish(AlertSeverity severity, string source, string title, string detail)
    {
        var item = new AlertItem(DateTime.Now, severity, source, Limit(title, 120), Limit(detail, 300));
        UiThread.Post(() =>
        {
            Alerts.Insert(0, item);
            while (Alerts.Count > MaxAlerts) Alerts.RemoveAt(Alerts.Count - 1);
            Published?.Invoke(item);
        });
    }

    // Les détails peuvent contenir des noms de fichiers ou de commandes non fiables : on borne la taille
    // et on retire les caractères de contrôle.
    private static string Limit(string text, int max)
    {
        string clean = new(text.Where(c => !char.IsControl(c)).ToArray());
        return clean.Length > max ? clean[..max] + "…" : clean;
    }
}
