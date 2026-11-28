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
    LockdownController lockdown,
    ILockdownBackend lockdownBackend,
    CoreGuard.Network.INetworkGuard firewall,
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
    private CredentialGuard? _credentials;
    private RemoteLockWatcher? _remoteLock;
    private ParanoiaGuard? _paranoia;
    private RemoteControlServer? _remote;
    private RemoteControlConfig? _remoteConfig;
    private DateTime _lastEngage = DateTime.MinValue;
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
        StartCredentialGuard();
        StartLockdown();
        StartParanoia();
        StartRemoteControl();
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

            case IpcContract.Types.LockdownEngage:
                return new IpcEnvelope(IpcContract.Types.LockdownResult, StopResult: Engage(
                    Sanitize(request.Lockdown?.Reason) ?? "demande de l'utilisateur", request.Lockdown?.CutNetwork ?? false));

            case IpcContract.Types.UnlockRequest:
            {
                StopResult check = stopAuthenticator.Verify(request.Stop);
                if (!check.Accepted)
                {
                    Publish("Critical", "Verrouillage", "Déverrouillage refusé", check.Message);
                    return new IpcEnvelope(IpcContract.Types.LockdownResult, StopResult: check);
                }
                lockdown.Release();
                Publish("Warning", "Verrouillage", "PC déverrouillé", "Mot de passe de protection vérifié : blocages levés.");
                return new IpcEnvelope(IpcContract.Types.LockdownResult, StopResult: new StopResult(true, "PC déverrouillé."));
            }

            case IpcContract.Types.ParanoiaEnable:
                return new IpcEnvelope(IpcContract.Types.ParanoiaResult, StopResult: _paranoia?.Enable()
                    ?? new StopResult(false, "Mode Paranoïa indisponible."));

            case IpcContract.Types.ParanoiaDisable:
            {
                // Désactiver affaiblit la protection : mot de passe de protection exigé s'il est configuré
                if (stopAuthenticator.IsConfigured)
                {
                    StopResult check = stopAuthenticator.Verify(request.Stop);
                    if (!check.Accepted)
                    {
                        Publish("Critical", "Paranoïa", "Désactivation refusée", check.Message);
                        return new IpcEnvelope(IpcContract.Types.ParanoiaResult, StopResult: check);
                    }
                }
                return new IpcEnvelope(IpcContract.Types.ParanoiaResult, StopResult: _paranoia?.Disable()
                    ?? new StopResult(false, "Mode Paranoïa indisponible."));
            }

            case IpcContract.Types.RemotePair:
            case IpcContract.Types.RemoteRevoke:
            {
                // La clé d'appareil permet de déverrouiller le PC : mot de passe de protection exigé
                StopResult check = stopAuthenticator.Verify(request.Stop);
                if (!check.Accepted)
                {
                    Publish("Critical", "Contrôle à distance", "Association refusée", check.Message);
                    return new IpcEnvelope(IpcContract.Types.RemoteResult, Remote: new RemotePairing(false, 0, null, [], check.Message));
                }
                return new IpcEnvelope(IpcContract.Types.RemoteResult,
                    Remote: request.Type == IpcContract.Types.RemotePair ? PairPhone() : RevokePhone());
            }

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

    // ---------- Verrouillage d'urgence ----------

    private void StartLockdown()
    {
        lockdown.Warning += w => logger.LogWarning("Verrouillage : {Warning}", w);
        lockdown.Changed += _ => _server?.BroadcastStatus();
        lockdown.Reassert(); // verrouillage en cours avant un redémarrage : ré-appliqué
        if (lockdown.State.Engaged) logger.LogWarning("Verrouillage d'urgence toujours actif (depuis {Since}).", lockdown.State.SinceUtc);

        var remote = RemoteLockConfig.Load(ServiceHost.RemoteLockPath);
        if (remote is not null && OperatingSystem.IsWindows())
        {
            _remoteLock = new RemoteLockWatcher(remote, reason => Engage(reason, cutNetwork: false),
                (title, detail) => Publish("Critical", "Verrouillage", title, detail), logger);
            _remoteLock.Start();
        }
    }

    private StopResult Engage(string reason, bool cutNetwork)
    {
        if (lockdown.State.Engaged) return new StopResult(true, "PC déjà verrouillé.");
        if (DateTime.UtcNow - _lastEngage < TimeSpan.FromSeconds(10)) return new StopResult(false, "Réessayez dans quelques secondes.");
        _lastEngage = DateTime.UtcNow;
        lockdown.Engage(reason, cutNetwork);
        Publish("Critical", "Verrouillage", "PC verrouillé",
            $"Motif : {reason}. USB bloqué, nouveaux périphériques refusés{(cutNetwork ? ", réseau coupé" : "")}.");
        logger.LogWarning("Verrouillage d'urgence : {Reason}", reason);
        return new StopResult(true, "PC verrouillé.");
    }

    private static string? Sanitize(string? text) =>
        string.IsNullOrWhiteSpace(text) ? null : new string(text.Where(c => !char.IsControl(c)).Take(100).ToArray());

    // ---------- Mode Paranoïa ----------

    private void StartParanoia()
    {
        if (!OperatingSystem.IsWindows()) return;
        _remoteConfig = RemoteControlConfig.Load(ServiceHost.RemoteControlPath) is { Enabled: true } cfg ? cfg : null;
        _paranoia = new ParanoiaGuard(actions, lockdownBackend, () => lockdown.State.Engaged, Publish, logger, ServiceHost.ParanoiaStatePath,
            () => _remoteConfig is { } r ? [(ushort)r.Port] : []);
        if (_etw is not null) _etw.ProcessStarted += (_, e) => _paranoia.OnProcessStarted(e.Pid, e.Image);
        _paranoia.Reassert(); // actif avant un redémarrage : ré-appliqué
        if (_paranoia.Enabled) logger.LogWarning("Mode Paranoïa toujours actif : {Status}", _paranoia.StatusText);
        _server?.BroadcastStatus();
    }

    // ---------- Contrôle à distance (téléphone, réseau local / point d'accès) ----------

    private void StartRemoteControl()
    {
        _remoteConfig ??= RemoteControlConfig.Load(ServiceHost.RemoteControlPath) is { Enabled: true } cfg ? cfg : null;
        if (_remoteConfig is null) return;
        try
        {
            _remote = new RemoteControlServer(_remoteConfig, ExecuteRemote, RemoteStatus, Publish, logger);
            _remote.Start();
            if (firewall is CoreGuard.Network.WindowsFirewall wf && wf.CanManageFirewall)
                wf.AllowInboundPortFromLocalSubnet("Controle a distance", _remoteConfig.Port);
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or CoreGuard.Network.NetworkGuardException or UnauthorizedAccessException)
        {
            logger.LogWarning("Contrôle à distance indisponible : {Message}", ex.Message);
            _remote?.Dispose();
            _remote = null;
        }
        _server?.BroadcastStatus();
    }

    private RemotePairing PairPhone()
    {
        _remote?.Dispose();
        _remote = null;
        _remoteConfig = RemoteControlConfig.CreateNew();
        _remoteConfig.Save(ServiceHost.RemoteControlPath);
        StartRemoteControl();
        _paranoia?.RefreshFirewall();
        Publish("Warning", "Contrôle à distance", "Téléphone associé",
            "Toute association précédente est révoquée. Scannez le QR code affiché par CoreGuard avec le téléphone.");
        return _remote is null
            ? new RemotePairing(false, 0, null, [], "Port " + _remoteConfig.Port + " indisponible : contrôle à distance non démarré.")
            : new RemotePairing(true, _remoteConfig.Port, _remoteConfig.Key, _remoteConfig.Urls(), "Téléphone prêt à être associé.");
    }

    private RemotePairing RevokePhone()
    {
        _remote?.Dispose();
        _remote = null;
        _remoteConfig = null;
        try { File.Delete(ServiceHost.RemoteControlPath); } catch (IOException) { }
        if (firewall is CoreGuard.Network.WindowsFirewall wf && wf.CanManageFirewall) wf.RemoveRule("Controle a distance");
        _paranoia?.RefreshFirewall();
        _server?.BroadcastStatus();
        Publish("Warning", "Contrôle à distance", "Téléphone révoqué", "Le contrôle à distance est désactivé.");
        return new RemotePairing(false, 0, null, [], "Contrôle à distance désactivé.");
    }

    private (bool Ok, string Message) ExecuteRemote(string action)
    {
        StopResult r = action switch
        {
            "lock" => Engage("ordre du téléphone associé", cutNetwork: false),
            "unlock" => ReleaseLockdown(),
            "paranoia-on" => _paranoia?.Enable() ?? new StopResult(false, "Mode Paranoïa indisponible."),
            "paranoia-off" => _paranoia?.Disable() ?? new StopResult(false, "Mode Paranoïa indisponible."),
            _ => new StopResult(false, "Action inconnue.")
        };
        _server?.BroadcastStatus();
        return (r.Accepted, r.Message);
    }

    private StopResult ReleaseLockdown()
    {
        if (!lockdown.State.Engaged) return new StopResult(true, "PC déjà déverrouillé.");
        lockdown.Release();
        Publish("Warning", "Verrouillage", "PC déverrouillé", "Ordre signé du téléphone associé.");
        return new StopResult(true, "PC déverrouillé.");
    }

    private object RemoteStatus() => new { lockdown = lockdown.State.Engaged, paranoia = _paranoia?.Enabled ?? false, machine = Environment.MachineName };

    // ---------- Anti-infostealer ----------

    private void StartCredentialGuard()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var guard = new CredentialGuard(actions, Publish, logger);
            guard.Start();
            _credentials = guard;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogError("Anti-infostealer indisponible : {Message}", ex.Message);
        }
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
        var credentialGuard = _credentials;
        var credentials = credentialGuard is { Listening: true, WatchedFiles: > 0 }
            ? new ModuleStatus(ServiceModules.Credentials, "Active", credentialGuard.StatusText)
            : new ModuleStatus(ServiceModules.Credentials, "Unavailable", credentialGuard?.StatusText ?? "Non démarré");
        var ls = lockdown.State;
        string remoteText = _remoteLock is null ? "à distance : non configuré" : "à distance : actif";
        var lockdownModule = ls.Engaged
            ? new ModuleStatus(ServiceModules.Lockdown, "Active", $"Verrouillé depuis {ls.SinceUtc?.ToLocalTime():HH:mm} : {ls.Reason}")
            : new ModuleStatus(ServiceModules.Lockdown, "Disabled", $"Déverrouillé ({remoteText})");
        var paranoiaGuard = _paranoia;
        var paranoia = paranoiaGuard is null
            ? new ModuleStatus(ServiceModules.Paranoia, "Unavailable", "Non démarré")
            : new ModuleStatus(ServiceModules.Paranoia, paranoiaGuard.Enabled ? "Active" : "Disabled", paranoiaGuard.StatusText);
        var remoteConfig = _remoteConfig;
        var remote = remoteConfig is null
            ? new ModuleStatus(ServiceModules.Remote, "Disabled", "Aucun téléphone associé")
            : _remote is null
                ? new ModuleStatus(ServiceModules.Remote, "Unavailable", $"Port {remoteConfig.Port} indisponible")
                : new ModuleStatus(ServiceModules.Remote, "Active",
                    $"Téléphone associé le {remoteConfig.PairedUtc.ToLocalTime():dd/MM HH:mm}, port {remoteConfig.Port} : " +
                    string.Join(", ", RemoteControlConfig.LocalAddresses()));
        var amsi = AmsiProviderRegistered()
            ? new ModuleStatus(ServiceModules.Amsi, "Active", $"Fournisseur AMSI enregistré : {_amsiScanned} contenu(s) analysé(s), {_amsiBlocked} bloqué(s)")
            : new ModuleStatus(ServiceModules.Amsi, "Unavailable", "Fournisseur AMSI non enregistré (scripts/install-service.ps1)");
        return new ServiceStatus(IpcContract.ProtocolVersion, Environment.ProcessId, _startedUtc,
            actions.Name, actions.IsKernelBacked, Environment.IsPrivilegedProcess, [behavior, canaries, credentials, amsi, memory, lockdownModule, paranoia, remote, selfDefense])
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
        _credentials?.Dispose(); // retire le profil leurre
        _remoteLock?.Dispose();
        _remote?.Dispose();
        _paranoia?.Dispose(); // session WFP dynamique fermée : filtres retirés (l'état reste enregistré pour le redémarrage)
        _credentials = null;
        _canaries = null;
        if (_server is not null) await _server.DisposeAsync();
        _server = null;
        await base.StopAsync(cancellationToken);
    }
}
