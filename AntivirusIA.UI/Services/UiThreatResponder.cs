using AntivirusIA.Core.Interfaces;
using AntivirusIA.UI.Models;
using CoreGuard.RealTime;

namespace AntivirusIA.UI.Services;

/// <summary>
/// Réaction aux menaces temps réel : publie dans le flux d'alertes.
/// Les actions destructives (kill) restent volontairement SIMULÉES : le PID suspect n'est qu'une heuristique.
/// </summary>
public sealed class UiThreatResponder(AlertHub alerts, IQuarantineService quarantine) : IThreatResponder
{
    public Task OnCanaryTriggeredAsync(CanaryAlert alert, CancellationToken ct)
    {
        alerts.Publish(AlertSeverity.Critical, "Canari",
            $"Fichier leurre {alert.OperationType}",
            $"{Path.GetFileName(alert.CanaryPath)} - PID suspect : {alert.SuspectPid?.ToString() ?? "inconnu"} (comportement de type ransomware)");
        return Task.CompletedTask;
    }

    public Task KillProcessAsync(int pid)
    {
        alerts.Publish(AlertSeverity.Warning, "Réponse", "Arrêt de processus simulé", $"PID {pid} (aucune action réelle)");
        return Task.CompletedTask;
    }

    public async Task QuarantineAsync(string path, string reason)
    {
        try { await quarantine.QuarantineAsync(path, reason); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            alerts.Publish(AlertSeverity.Warning, "Réponse", "Quarantaine impossible", ex.Message);
        }
    }
}
