// Dossier nommé UiModels (et non Models) car le .gitignore du dépôt ignore "models/" ; le namespace reste AntivirusIA.UI.Models.
namespace AntivirusIA.UI.Models;

public enum AlertSeverity { Info, Warning, Critical }

/// <summary>Une entrée du flux d'alertes (les textes proviennent parfois de données non fiables : affichage en texte brut uniquement).</summary>
public sealed record AlertItem(DateTime WhenLocal, AlertSeverity Severity, string Source, string Title, string Detail)
{
    public string TimeText => WhenLocal.ToString("HH:mm:ss");
}
