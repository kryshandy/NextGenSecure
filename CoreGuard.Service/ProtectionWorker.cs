using AntivirusIA.Core.Interfaces;
using CoreGuard.Behavior;
using CoreGuard.Ipc;
using CoreGuard.Response;

namespace CoreGuard.Service;

public static class ServiceIdentity
{
    public const string ServiceName = "CoreGuardService";
    public const string DisplayName = "CoreGuard — Protection";
}

/// <summary>
/// Cœur du service : héberge les modules qui ont besoin de privilèges système et ne dépendent pas de la
/// session de l'utilisateur (télémétrie ETW des processus, canaris anti-ransomware avec attribution par audit NTFS,
/// et réponse associée), publie état et alertes sur
/// le pipe <see cref="IpcContract.PipeName"/>, et assure l'auto-défense :
/// - DACL du processus durcie (arrêt, suspension, injection refusés hors SYSTEM) ;
/// - watchdog mutuel (chaque processus relance l'autre s'il est tué) ;
/// - arrêt légitime uniquement par mot de passe (défi-réponse HMAC), qui prévient le watchdog.
/// </summary>
public sealed class ProtectionWorker(
    IKernelActionProvider actions,
    UserModeActionProvider userMode,
    StopAuthenticator stopAuthenticator,
    WatchdogSupervisor watchdog,
    ScriptScanner scripts,
    ServiceOptions options,
    IHostApplicationLifetime lifetime,
    ILogger<ProtectionWorker> logger) : BackgroundService
{
    private readonly DateTime _startedUtc = DateTime.UtcNow;
    private readonly object _gate = new();
    private ModuleStatus _behavior = new(ServiceModules.Behavior, "Disabled", "Démarrage…");
    private ModuleStatus _selfDefense = new(ServiceModules.SelfDefense, "Disabled", "Désactivée (mode développement)");
    private PipeServer? _server;
    private EtwProcessMonitor? _etw;
    private CanaryGuard? _canaries;
    private MemoryGuard? _memory;
    private int _stopAccepted;
    private int _amsiScanned, _amsiBlocked;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _amsiAlerted = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _server = new PipeServer(ServiceHost.PipeName, BuildStatus, PipeServer.CreateServiceSecurity(), HandleCommand);
        _server.Error += (_, ex) => logger.LogWarning("Pipe IPC indisponible : {Message}", ex.Message);
        _server.ClientConnected += (_, pid) => logger.LogInformation("Interface connectée (PID {Pid}).", pid);
        _server.Start();

        // ETW d'abord : son démarrage ouvre le processus courant, ce que la DACL durcie restreint ensuite
        StartBehavior();
        StartCanaries();
        StartMemoryScan();
        if (options.Supervise) await StartSelfDefenseAsync();
        logger.LogInformation("CoreGuard démarré (PID {Pid}, élevé : {Elevated}, actions : {Provider}, auto-défense : {Harden}, mot de passe : {Pwd}).",
            Environment.ProcessId, Environment.IsPrivilegedProcess, actions.Name, options.Harden, stopAuthenticator.IsConfigured);

        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Arrêt (authentifié ou arrêt de Windows)
        }
    }

    // ---------- Auto-défense ----------

    private async Task StartSelfDefenseAsync()
    {
        ActionResult self = options.Harden
            ? await actions.ProtectSelfAsync()
            : ActionResult.Fail("DACL non durcie (mode --supervise)");
        logger.LogInformation("Durcissement du processus : {Message}", self.Message);

        watchdog.Started += (_, pid) => userMode.AddProtectedProcess(pid);
        try
        {
            watchdog.Start(options.Harden);
            SetSelfDefense(self.Success ? "Active" : "Unavailable",
                self.Success ? "Processus durci, watchdog actif" : "Watchdog actif, durcissement refusé");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogError("Watchdog indisponible : {Message}", ex.Message);
            SetSelfDefense("Unavailable", "Watchdog indisponible");
        }
    }

    private IpcEnvelope? HandleCommand(IpcEnvelope request)
    {
        switch (request.Type)
        {
            case IpcContract.Types.Challenge:
                StopChallenge? challenge = stopAuthenticator.IssueChallenge();
                return challenge is null
                    ? new IpcEnvelope(IpcContract.Types.Error, Error: "Aucun mot de passe de protection n'est configuré (CoreGuard.Service.exe --set-password).")
                    : new IpcEnvelope(IpcContract.Types.Challenge, Challenge: challenge);

            case IpcContract.Types.StopRequest:
                StopResult result = stopAuthenticator.Verify(request.Stop);
                Publish(result.Accepted ? "Warning" : "Critical", "Auto-défense",
                    result.Accepted ? "Arrêt de la protection autorisé" : "Tentative d'arrêt refusée", result.Message);
                logger.LogWarning("Demande d'arrêt : {Message}", result.Message);
                if (result.Accepted && Interlocked.Exchange(ref _stopAccepted, 1) == 0)
                    _ = StopLegitimatelyAsync();
                return new IpcEnvelope(IpcContract.Types.StopResult, StopResult: result);

            case IpcContract.Types.AmsiScan:
                return new IpcEnvelope(IpcContract.Types.AmsiResult, AmsiVerdict: ScanScript(request.Amsi));

            default:
                return null;
        }
    }

    // ---------- AMSI ----------

    private AmsiVerdict ScanScript(AmsiScanRequest? request)
    {
        AmsiVerdict verdict = scripts.Evaluate(request);
        Interlocked.Increment(ref _amsiScanned);
        if (verdict.Detected) Interlocked.Increment(ref _amsiBlocked);

        if (verdict.Score >= ScriptScanner.SuspectScore)
        {
            string app = request?.App ?? "?";
            // Une alerte par application et par motif toutes les 30 s (PowerShell soumet chaque bloc de script)
            string key = app + "|" + verdict.Reason;
            DateTime now = DateTime.UtcNow;
            if (!_amsiAlerted.TryGetValue(key, out DateTime last) || now - last > TimeSpan.FromSeconds(30))
            {
                _amsiAlerted[key] = now;
                Publish(verdict.Detected ? "Critical" : "Warning", "AMSI",
                    verdict.Detected ? $"Script bloqué : {app}" : $"Script suspect : {app}",
                    $"Score {verdict.Score}/100 — {verdict.Reason}");
                logger.LogWarning("AMSI {Verdict} ({App}, score {Score}) : {Reason}",
                    verdict.Detected ? "bloqué" : "suspect", app, verdict.Score, verdict.Reason);
            }
        }
        return verdict;
    }

    private static bool AmsiProviderRegistered()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AmsiProviderInfo.ProvidersKey);
            return key is not null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task StopLegitimatelyAsync()
    {
        watchdog.SignalLegitimateStop();
        await Task.Delay(750); // laisse partir la réponse au client et le signal au watchdog
        lifetime.StopApplication();
    }

    // ---------- Anti-ransomware (canaris + audit NTFS) ----------

    private void StartCanaries()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var guard = new CanaryGuard(actions, Publish, logger);
            guard.Start();
            _canaries = guard;
            logger.LogInformation("Anti-ransomware : {Status}", guard.StatusText);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogError("Canaris indisponibles : {Message}", ex.Message);
        }
        _server?.BroadcastStatus();
    }

    // ---------- Scan mémoire (fileless) ----------

    private void StartMemoryScan()
    {
        // Exclus : CoreGuard lui-même et son watchdog
        ISet<int> Excluded()
        {
            var set = new HashSet<int> { Environment.ProcessId };
            if (watchdog.WatchdogPid is int wd) set.Add(wd);
            return set;
        }
        _memory = new MemoryGuard(actions, Publish, Excluded, logger);
        _memory.Start();
        logger.LogInformation("Scan mémoire actif (toutes les {Seconds} s).", MemoryGuard.Interval.TotalSeconds);
    }

    // ---------- Comportement (ETW) ----------

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

    // ---------- État ----------

    private void Publish(string severity, string source, string title, string detail) =>
        _server?.Broadcast(new ServiceAlert(severity, source, title, detail, DateTime.UtcNow));

    private void SetBehavior(string state, string text)
    {
        lock (_gate) _behavior = new ModuleStatus(ServiceModules.Behavior, state, text);
        _server?.BroadcastStatus();
    }

    private void SetSelfDefense(string state, string text)
    {
        lock (_gate) _selfDefense = new ModuleStatus(ServiceModules.SelfDefense, state, text);
        _server?.BroadcastStatus();
    }

    private ServiceStatus BuildStatus()
    {
        ModuleStatus behavior, selfDefense;
        lock (_gate) { behavior = _behavior; selfDefense = _selfDefense; }
        var guard = _canaries;
        var canaries = guard is { CanaryCount: > 0 }
            ? new ModuleStatus(ServiceModules.Canaries, "Active", guard.StatusText)
            : new ModuleStatus(ServiceModules.Canaries, "Unavailable", guard?.StatusText ?? "Non démarrés");
        var memoryGuard = _memory;
        var memory = memoryGuard is null
            ? new ModuleStatus(ServiceModules.Memory, "Unavailable", "Scan mémoire non démarré")
            : new ModuleStatus(ServiceModules.Memory, "Active", memoryGuard.StatusText);
        var amsi = AmsiProviderRegistered()
            ? new ModuleStatus(ServiceModules.Amsi, "Active", $"Fournisseur AMSI enregistré : {_amsiScanned} contenu(s) analysé(s), {_amsiBlocked} bloqué(s)")
            : new ModuleStatus(ServiceModules.Amsi, "Unavailable", "Fournisseur AMSI non enregistré (scripts/install-service.ps1)");
        return new ServiceStatus(IpcContract.ProtocolVersion, Environment.ProcessId, _startedUtc,
            actions.Name, actions.IsKernelBacked, Environment.IsPrivilegedProcess, [behavior, canaries, amsi, memory, selfDefense])
        {
            StopPasswordConfigured = stopAuthenticator.IsConfigured
        };
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        // Tout arrêt gracieux de l'hôte est légitime ici (sc stop est refusé en service Windows) :
        // arrêt authentifié ou arrêt de Windows. On prévient le watchdog pour qu'il ne relance pas.
        watchdog.SignalLegitimateStop();
        _etw?.Dispose();
        _etw = null;
        _canaries?.Dispose(); // retire les canaris du disque
        _memory?.Dispose();
        _memory = null;
        _canaries = null;
        if (_server is not null) await _server.DisposeAsync();
        _server = null;
        await base.StopAsync(cancellationToken);
    }
}
