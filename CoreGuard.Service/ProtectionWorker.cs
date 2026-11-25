using AntivirusIA.Core.Interfaces;
using CoreGuard.Behavior;
using CoreGuard.Ipc;

namespace CoreGuard.Service;

public static class ServiceIdentity
{
    public const string ServiceName = "CoreGuardService";
    public const string DisplayName = "CoreGuard — Protection";
}

/// <summary>
/// Cœur du service : héberge les modules qui ont besoin de privilèges système et ne dépendent pas de la
/// session de l'utilisateur (aujourd'hui : télémétrie ETW des processus et réponse associée), et publie
/// état et alertes aux interfaces connectées par le pipe <see cref="IpcContract.PipeName"/>.
/// Les modules liés à la session (presse-papiers, caméra/micro, canaris, téléchargements) restent dans l'UI.
/// </summary>
public sealed class ProtectionWorker(IKernelActionProvider actions, ILogger<ProtectionWorker> logger) : BackgroundService
{
    private readonly DateTime _startedUtc = DateTime.UtcNow;
    private readonly object _gate = new();
    private ModuleStatus _behavior = new(ServiceModules.Behavior, "Disabled", "Démarrage…");
    private PipeServer? _server;
    private EtwProcessMonitor? _etw;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _server = new PipeServer(IpcContract.PipeName, BuildStatus, PipeServer.CreateServiceSecurity());
        _server.Error += (_, ex) => logger.LogWarning("Pipe IPC indisponible : {Message}", ex.Message);
        _server.ClientConnected += (_, pid) => logger.LogInformation("Interface connectée (PID {Pid}).", pid);
        _server.Start();

        StartBehavior();
        logger.LogInformation("CoreGuard démarré (PID {Pid}, élevé : {Elevated}, actions : {Provider}).",
            Environment.ProcessId, Environment.IsPrivilegedProcess, actions.Name);

        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Arrêt demandé par le gestionnaire de services
        }
    }

    private void StartBehavior()
    {
        var monitor = new EtwProcessMonitor(new BehaviorRuleEngine());
        monitor.Warning += (_, w) => logger.LogWarning("{Warning}", w);
        monitor.AlertRaised += (_, a) => OnBehaviorAlert(a);

        if (monitor.Start())
        {
            _etw = monitor;
            SetBehavior("Active", "Surveillance ETW active (service)");
        }
        else
        {
            monitor.Dispose();
            SetBehavior("Unavailable", Environment.IsPrivilegedProcess ? "Session ETW impossible" : "Droits administrateur requis");
        }
    }

    private void OnBehaviorAlert(BehaviorAlert alert)
    {
        Publish(alert.Severity >= 80 ? "Critical" : "Warning", "Comportement", alert.Rule, alert.Detail);

        // Suppression des clichés instantanés : PID exact fourni par ETW, arrêt immédiat
        if (alert.Rule == BehaviorRuleEngine.RuleShadowDelete && alert.Pid is int pid)
        {
            _ = Task.Run(async () =>
            {
                ActionResult result = await actions.TerminateProcessAsync(pid, "suppression des clichés instantanés (anti-ransomware)");
                Publish(result.Success ? "Critical" : "Warning", "Réponse",
                    result.Success ? "Processus arrêté" : "Arrêt impossible", result.Message);
                logger.LogWarning("Réponse anti-ransomware : {Message}", result.Message);
            });
        }
    }

    private void Publish(string severity, string source, string title, string detail) =>
        _server?.Broadcast(new ServiceAlert(severity, source, title, detail, DateTime.UtcNow));

    private void SetBehavior(string state, string text)
    {
        lock (_gate) _behavior = new ModuleStatus(ServiceModules.Behavior, state, text);
        _server?.BroadcastStatus();
    }

    private ServiceStatus BuildStatus()
    {
        ModuleStatus behavior;
        lock (_gate) behavior = _behavior;
        return new ServiceStatus(IpcContract.ProtocolVersion, Environment.ProcessId, _startedUtc,
            actions.Name, actions.IsKernelBacked, Environment.IsPrivilegedProcess, [behavior]);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _etw?.Dispose();
        _etw = null;
        if (_server is not null) await _server.DisposeAsync();
        _server = null;
        await base.StopAsync(cancellationToken);
    }
}
