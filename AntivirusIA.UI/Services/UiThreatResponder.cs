using AntivirusIA.Core.Interfaces;
using AntivirusIA.UI.Models;
using CoreGuard.RealTime;

namespace AntivirusIA.UI.Services;

/// <summary>
/// Réaction aux menaces temps réel : publie dans le flux d'alertes et exécute les actions via
/// <see cref="IKernelActionProvider"/> (mode utilisateur aujourd'hui, driver plus tard).
/// Canaris : le PID suspect n'est qu'une estimation (pas d'attribution fiable sans driver) ;
/// il est donc signalé, jamais arrêté automatiquement.
/// </summary>
public sealed class UiThreatResponder(AlertHub alerts, IQuarantineService quarantine, IKernelActionProvider actions) : IThreatResponder
{
    public Task OnCanaryTriggeredAsync(CanaryAlert alert, CancellationToken ct)
    {
        alerts.Publish(AlertSeverity.Critical, "Canari",
            $"Fichier leurre {alert.OperationType}",
            $"{Path.GetFileName(alert.CanaryPath)} - PID suspect : {alert.SuspectPid?.ToString() ?? "inconnu"} (comportement de type ransomware)");
        return Task.CompletedTask;
    }

    public Task KillProcessAsync(int pid) => TerminateAsync(pid, "menace détectée");

    /// <summary>Arrête un processus et publie le résultat (succès ou refus) dans le flux d'alertes.</summary>
    public async Task<ActionResult> TerminateAsync(int pid, string reason, CancellationToken ct = default)
    {
        ActionResult result = await actions.TerminateProcessAsync(pid, reason, ct).ConfigureAwait(false);
        alerts.Publish(result.Success ? AlertSeverity.Critical : AlertSeverity.Warning, "Réponse",
            result.Success ? "Processus arrêté" : "Arrêt impossible", result.Message);
        return result;
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
