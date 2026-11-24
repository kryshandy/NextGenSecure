using System.Diagnostics;

namespace CoreGuard.RealTime;

/// <summary>
/// Responder par défaut : journalise uniquement (aucune action destructive).
/// </summary>
public sealed class LoggingThreatResponder : IThreatResponder
{
    private readonly Action<string> _log;

    /// <param name="log">Sink de journalisation ; par défaut <see cref="Trace.WriteLine(string)"/>.</param>
    public LoggingThreatResponder(Action<string>? log = null) => _log = log ?? (m => Trace.WriteLine(m));

    public Task OnCanaryTriggeredAsync(CanaryAlert alert, CancellationToken ct)
    {
        _log($"[CoreGuard] ALERTE canari {alert.OperationType} : {alert.CanaryPath} (PID suspect : {alert.SuspectPid?.ToString() ?? "inconnu"}) à {alert.WhenUtc:O}");
        return Task.CompletedTask;
    }

    public Task KillProcessAsync(int pid)
    {
        _log($"[CoreGuard] (simulation) KillProcess pid={pid}");
        return Task.CompletedTask;
    }

    public Task QuarantineAsync(string path, string reason)
    {
        _log($"[CoreGuard] (simulation) Quarantaine {path} : {reason}");
        return Task.CompletedTask;
    }
}
