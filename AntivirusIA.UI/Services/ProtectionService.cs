using System.Collections.ObjectModel;
using AntivirusIA.UI.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CoreGuard.Behavior;
using CoreGuard.Network;
using CoreGuard.Privacy;
using CoreGuard.RealTime;

namespace AntivirusIA.UI.Services;

public enum ModuleState { Disabled, Active, Unavailable }

/// <summary>Un module de protection tel qu'affiché sur le tableau de bord.</summary>
public sealed partial class ProtectionModule(string name, string description, string iconKey) : ObservableObject
{
    public string Name { get; } = name;
    public string Description { get; } = description;
    public string IconKey { get; } = iconKey;

    [ObservableProperty] private ModuleState _state = ModuleState.Disabled;
    [ObservableProperty] private string _statusText = "Désactivé";
}

/// <summary>
/// Pilote les modules temps réel (canaris, comportement, persistance, réseau, vie privée, surveillance de dossiers).
/// Chaque démarrage est protégé : un module en échec passe en « Indisponible » sans empêcher les autres.
/// Les événements arrivent sur des threads d'arrière-plan : tout passe par AlertHub / UiThread.
/// </summary>
public sealed class ProtectionService : IDisposable
{
    private readonly AppSettings _settings;
    private readonly AlertHub _alerts;
    private readonly ScanService _scan;
    private readonly UiThreatResponder _responder;
    private readonly INetworkGuard _network;
    private readonly ParanoiaMode _paranoia = new();
    private readonly object _gate = new();
    private readonly SemaphoreSlim _downloadScanLock = new(1, 1);

    private RealtimeFileMonitor? _files;
    private CanaryManager? _canaries;
    private EtwProcessMonitor? _etw;
    private PersistenceWatcher? _persistence;
    private ClipboardGuardian? _clipboard;
    private SensorMonitor? _sensors;
    private CoreGuard.Devices.BadUsbMonitor? _badUsb;
    private Timer? _networkTimer;
    private bool _disposed;

    public ProtectionModule Files { get; } = new("Surveillance des fichiers", "Analyse automatique des nouveaux téléchargements", "Icon.Folder");
    public ProtectionModule Canaries { get; } = new("Fichiers leurres", "Détection de ransomware par canaris", "Icon.Bug");
    public ProtectionModule Behavior { get; } = new("Comportement des processus", "Règles ETW (Office vers shell, copies fantômes)", "Icon.Scan");
    public ProtectionModule Persistence { get; } = new("Persistance", "Clés Run, tâches planifiées, services", "Icon.Restore");
    public ProtectionModule Network { get; } = new("Réseau", "Inspection des ports et pare-feu", "Icon.Globe");
    public ProtectionModule Clipboard { get; } = new("Presse-papiers", "Anti-détournement d'adresses crypto", "Icon.File");
    public ProtectionModule Sensors { get; } = new("Webcam et micro", "Alerte sur utilisation par une application", "Icon.Eye");
    public ProtectionModule Paranoia { get; } = new("Mode paranoïa", "Durcissement renforcé (USB, pare-feu, exécution)", "Icon.Shield");
    public ProtectionModule BadUsb { get; } = new("Clavier (BadUSB)", "Bloque la frappe automatique d'un faux clavier USB", "Icon.Keyboard");

    public ObservableCollection<ProtectionModule> Modules { get; }

    /// <summary>Levé (thread UI) quand l'état d'un module a changé.</summary>
    public event Action? ModulesChanged;

    private readonly ServiceLink _service;
    private readonly LockdownUiController _lockdown;
    private readonly PersistencePromptService _persistencePrompt;
    private readonly IDialogService _dialogs;
    private readonly SettingsStore _store;
    private UserDirExecutionGuard? _localExec;
    private int _paranoiaBusy;

    public ProtectionService(AppSettings settings, AlertHub alerts, ScanService scan, UiThreatResponder responder, INetworkGuard network,
        ServiceLink service, LockdownUiController lockdown, PersistencePromptService persistencePrompt, IDialogService dialogs, SettingsStore store)
    {
        _dialogs = dialogs;
        _store = store;
        _settings = settings;
        _alerts = alerts;
        _scan = scan;
        _responder = responder;
        _network = network;
        _service = service;
        _lockdown = lockdown;
        _persistencePrompt = persistencePrompt;
        Modules = [Files, Canaries, Behavior, Persistence, Network, Clipboard, Sensors, BadUsb, Paranoia];

        // Le service (SYSTEM) prend la télémétrie ETW dès qu'il est joignable, et la rend s'il disparaît
        _service.StatusChanged += () => _ = ApplyServiceModulesAsync();
    }

    public int ActiveCount => Modules.Count(m => m.State == ModuleState.Active);

    /// <summary>Applications utilisant actuellement la caméra ou le micro (hors liste blanche).</summary>
    public IReadOnlyList<CoreGuard.Privacy.SensorUsage> ActiveSensorUsages()
    {
        try { return _sensors?.Snapshot() ?? []; }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return []; }
    }

    /// <summary>Levé (thread quelconque) quand une application commence ou cesse d'utiliser un capteur.</summary>
    public event Action? SensorsChanged;

    /// <summary>Applique les réglages courants (démarre/arrête les modules). Exécuté hors thread UI.</summary>
    public Task ApplyAsync() => Task.Run(() =>
    {
        lock (_gate)
        {
            if (_disposed) return;
            ApplyFiles();
            ApplyCanaries();
            ApplyBehavior();
            ApplyPersistence();
            ApplyNetwork();
            ApplyClipboard();
            ApplySensors();
            ApplyBadUsb();
            ApplyParanoia(userAction: true);
        }
        UiThread.Post(() => ModulesChanged?.Invoke());
    });

    // ---- Surveillance des téléchargements : analyse automatique des nouveaux fichiers ----
    private void ApplyFiles()
    {
        Stop(ref _files, f => f.Dispose());
        if (!_settings.MonitorDownloads) { Set(Files, ModuleState.Disabled, "Désactivé"); return; }

        Guard(Files, () =>
        {
            var monitor = new RealtimeFileMonitor();
            monitor.NewFileDetected += OnNewFile;
            string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            var watched = monitor.Start([downloads], includeSubdirectories: false);
            if (watched.Count == 0) { monitor.Dispose(); Set(Files, ModuleState.Unavailable, "Dossier Téléchargements introuvable"); return; }
            _files = monitor;
            Set(Files, ModuleState.Active, "Téléchargements : verdict vert / orange / rouge (origine, signature, moteurs)");
        });
    }

    private void OnNewFile(object? sender, string path)
    {
        string ext = Path.GetExtension(path);
        if (ext is ".tmp" or ".crdownload" or ".part" or ".partial") return;

        _ = Task.Run(async () =>
        {
            await _downloadScanLock.WaitAsync();
            try
            {
                await Task.Delay(1500); // laisse le navigateur terminer l'écriture
                var outcome = await _scan.ScanFileAsync(path);
                ReportDownload(path, outcome);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException)
            {
                // Fichier déjà supprimé ou verrouillé : rien à faire
            }
            finally { _downloadScanLock.Release(); }
        });
    }

    // Smart Download Guard : marque du Web (Zone.Identifier) + signature + verdict → vert / orange / rouge
    private void ReportDownload(string path, ScanOutcome outcome)
    {
        var motw = MarkOfTheWeb.Read(path);
        var trust = outcome.Result.Trust;
        var assessment = DownloadRisk.Assess(path, motw, trust?.IsTrusted ?? false, trust?.Publisher, outcome.Verdict.ToString(), outcome.Score);

        string level = assessment.Level switch { DownloadLevel.Red => "rouge", DownloadLevel.Orange => "orange", _ => "vert" };
        _alerts.Publish(assessment.Level switch { DownloadLevel.Red => AlertSeverity.Critical, DownloadLevel.Orange => AlertSeverity.Warning, _ => AlertSeverity.Info },
            "Téléchargements", $"Téléchargement {level} : {Path.GetFileName(path)}", string.Join(" ; ", assessment.Reasons));

        // Fenêtre pour tout ce qui peut s'exécuter, et pour tout fichier orange ou rouge
        if (assessment.Level == DownloadLevel.Green && !DownloadRisk.IsRunnable(path)) return;
        UiThread.Post(() => new Views.DownloadGuardWindow(path, motw, assessment, outcome.Quarantined, async () =>
            await _scan.QuarantineAsync(outcome)
                ? "Fichier mis en quarantaine (restaurable depuis la page Quarantaine)."
                : "Mise en quarantaine impossible (fichier ouvert ou déjà déplacé ?).").Show());
    }

    // ---- Canaris anti-ransomware ----
    private void ApplyCanaries()
    {
        if (_canaries is not null) { _canaries.Remove(); _canaries.Dispose(); _canaries = null; }

        // Service installé : il gère seul les canaris (avec arrêt du processus coupable si l'audit est actif)
        if (ServiceLink.ServiceInstalled)
        {
            if (_service.HandlesCanaries)
                Set(Canaries, ModuleState.Active, "Service : " + (_service.CanariesText ?? "actifs"));
            else
                Set(Canaries, ModuleState.Unavailable, "Gérés par le service CoreGuard (actuellement injoignable)");
            return;
        }

        if (!_settings.CanariesEnabled) { Set(Canaries, ModuleState.Disabled, "Désactivé"); return; }

        Guard(Canaries, () =>
        {
            var manager = new CanaryManager(_responder);
            var created = manager.Deploy(CanaryManager.DefaultFolders());
            if (created.Count == 0) { manager.Dispose(); Set(Canaries, ModuleState.Unavailable, "Aucun dossier accessible"); return; }
            _canaries = manager;
            Set(Canaries, ModuleState.Active, $"{created.Count} leurres déployés");
        });
    }

    // ---- Comportement des processus (ETW : droits administrateur requis) ----
    /// <summary>Réapplique les modules que le service peut assurer (changement d'état du service).</summary>
    public Task ApplyServiceModulesAsync() => Task.Run(() =>
    {
        lock (_gate)
        {
            if (_disposed) return;
            ApplyBehavior();
            ApplyCanaries();
            ApplyParanoia(userAction: false);
        }
        UiThread.Post(() => ModulesChanged?.Invoke());
    });

    private void ApplyBehavior()
    {
        Stop(ref _etw, m => m.Dispose());
        if (!_settings.BehaviorEnabled) { Set(Behavior, ModuleState.Disabled, "Désactivé"); return; }

        // Assurée par le service : pas de seconde session ETW dans l'UI (le service est SYSTEM, l'UI non)
        if (_service.HandlesBehavior)
        {
            Set(Behavior, ModuleState.Active, "Assurée par le service CoreGuard (SYSTEM)");
            return;
        }

        Guard(Behavior, () =>
        {
            var monitor = new EtwProcessMonitor(new BehaviorRuleEngine());
            monitor.AlertRaised += (_, a) =>
            {
                _alerts.Publish(a.Severity >= 80 ? AlertSeverity.Critical : AlertSeverity.Warning,
                    "Comportement", a.Rule, a.Detail);

                // Suppression des clichés instantanés : PID exact fourni par ETW, arrêt immédiat
                // (préparation typique d'un ransomware). En mode utilisateur, l'arrêt suit le démarrage :
                // une commande très rapide peut avoir agi avant ; le driver permettra de la bloquer en amont.
                if (a.Rule == BehaviorRuleEngine.RuleShadowDelete && a.Pid is int pid)
                    _ = _responder.TerminateAsync(pid, "suppression des clichés instantanés (anti-ransomware)");
            };
            if (monitor.Start()) { _etw = monitor; Set(Behavior, ModuleState.Active, "Surveillance ETW active"); }
            else { monitor.Dispose(); Set(Behavior, ModuleState.Unavailable, "Droits administrateur requis"); }
        });
    }

    // ---- Mécanismes de persistance ----
    private void ApplyPersistence()
    {
        Stop(ref _persistence, p => p.Dispose());
        if (!_settings.PersistenceEnabled) { Set(Persistence, ModuleState.Disabled, "Désactivé"); return; }

        Guard(Persistence, () =>
        {
            var watcher = new PersistenceWatcher();
            // Fenêtre Autoriser / Bloquer pour chaque nouvelle entrée de démarrage
            watcher.PersistenceDetected += (_, e) => _persistencePrompt.Handle(e);
            watcher.Start();
            _persistence = watcher;
            Set(Persistence, ModuleState.Active, "Run, tâches planifiées, dossier Démarrage, services : Autoriser / Bloquer");
        });
    }

    // ---- Réseau : inspection des ports (pare-feu = droits administrateur) ----
    private void ApplyNetwork()
    {
        _networkTimer?.Dispose();
        _networkTimer = new Timer(_ => RefreshNetwork(), null, TimeSpan.Zero, TimeSpan.FromSeconds(15));
    }

    private void RefreshNetwork()
    {
        try
        {
            int established = PortInspector.GetConnections().Count(c => string.Equals(c.State, "ESTABLISHED", StringComparison.OrdinalIgnoreCase));
            string admin = _network.CanManageFirewall ? "pare-feu pilotable" : "lecture seule (non administrateur)";
            Set(Network, ModuleState.Active, $"{established} connexions établies, {admin}");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Set(Network, ModuleState.Unavailable, "Inspection impossible");
        }
    }

    // ---- Presse-papiers ----
    private void ApplyClipboard()
    {
        Stop(ref _clipboard, c => c.Dispose());
        if (!_settings.ClipboardEnabled) { Set(Clipboard, ModuleState.Disabled, "Désactivé"); return; }

        Guard(Clipboard, () =>
        {
            var guardian = new ClipboardGuardian();
            guardian.AlertRaised += (_, a) => _alerts.Publish(
                a.Kind == ClipboardAlertKind.SecretCleared ? AlertSeverity.Info : AlertSeverity.Critical,
                "Presse-papiers", a.Kind.ToString(), a.Detail);
            guardian.Start();
            _clipboard = guardian;
            Set(Clipboard, ModuleState.Active, "Garde active");
        });
    }

    // ---- Webcam / micro ----
    private void ApplySensors()
    {
        Stop(ref _sensors, s => s.Dispose());
        if (!_settings.SensorsEnabled) { Set(Sensors, ModuleState.Disabled, "Désactivé"); return; }

        Guard(Sensors, () =>
        {
            var monitor = new SensorMonitor();
            monitor.UsageChanged += (_, u) =>
            {
                SensorsChanged?.Invoke();
                if (u.InUse)
                    _alerts.Publish(AlertSeverity.Warning, "Vie privée", $"{u.Sensor} utilisé", Path.GetFileName(u.Process));
            };
            monitor.Start();
            _sensors = monitor;
            Set(Sensors, ModuleState.Active, "Webcam et micro surveillés");
        });
    }

    // ---- BadUSB : hook clavier (session de l'utilisateur) ----
    private void ApplyBadUsb()
    {
        Stop(ref _badUsb, m => m.Dispose());
        if (!_settings.BadUsbEnabled) { Set(BadUsb, ModuleState.Disabled, "Désactivé"); return; }

        Guard(BadUsb, () =>
        {
            var monitor = new CoreGuard.Devices.BadUsbMonitor();
            monitor.InjectionDetected += (_, _) =>
            {
                if (_settings.LockOnBadUsb) _ = _lockdown.LockNowAsync("BadUSB détecté (frappe automatique)", _settings.LockdownCutsNetwork);
            };
            monitor.InjectionDetected += (_, a) => _alerts.Publish(AlertSeverity.Critical, "BadUSB",
                "Frappe automatique bloquée",
                $"{a.Verdict.CharsPerSecond:F0} car/s ({(a.Verdict.Kind == CoreGuard.Devices.InjectionKind.ExtremeRate ? "débit surhumain" : "cadence de machine")}"
                + $"{(a.Verdict.InjectedRatio > 0.5 ? ", injection logicielle" : ", périphérique matériel")}) : clavier bloqué {a.BlockedFor.TotalSeconds:F0} s");
            monitor.KeyboardConnected += (_, name) => _alerts.Publish(AlertSeverity.Warning, "BadUSB",
                "Nouveau clavier branché", $"Vigilance renforcée pendant 60 s : {name}");
            if (monitor.Start()) { _badUsb = monitor; Set(BadUsb, ModuleState.Active, "Cadence de frappe surveillée"); }
            else { monitor.Dispose(); Set(BadUsb, ModuleState.Unavailable, "Hook clavier impossible"); }
        });
    }

    // ---- Mode Paranoïa ----
    // Avec le service (SYSTEM) : USB bloqué, WFP natif (entrées refusées, outils détournés coupés d'Internet), blocage
    // d'exécution par ETW ; désactivation protégée par le mot de passe de protection.
    // Sans service : l'application bloque seule l'exécution non signée depuis les dossiers utilisateur (scrutation).
    private void ApplyParanoia(bool userAction)
    {
        if (_service.HandlesParanoia)
        {
            StopLocalExec();
            if (!userAction)
            {
                // Le service fait foi (mode ré-appliqué après un redémarrage, ou changé ailleurs)
                if (_settings.ParanoiaEnabled != _service.ParanoiaActive)
                {
                    bool active = _service.ParanoiaActive;
                    UiThread.Post(() => { _settings.ParanoiaEnabled = active; _store.Save(_settings); });
                }
                SetParanoiaFromService();
                return;
            }
            if (_settings.ParanoiaEnabled && !_service.ParanoiaActive) _ = EnableParanoiaViaServiceAsync();
            else if (!_settings.ParanoiaEnabled && _service.ParanoiaActive) UiThread.Post(DisableParanoiaViaService);
            else SetParanoiaFromService();
            return;
        }

        _paranoia.SetEnabled(_settings.ParanoiaEnabled);
        if (!_settings.ParanoiaEnabled)
        {
            if (StopLocalExec()) _alerts.Publish(AlertSeverity.Info, "Paranoïa", "Mode Paranoïa désactivé", "Blocage d'exécution levé.");
            Set(Paranoia, ModuleState.Disabled, "Désactivé");
            return;
        }
        if (_localExec is null)
        {
            var authenticode = new AntivirusIA.Engines.AuthenticodeVerifier();
            _localExec = new UserDirExecutionGuard(
                path => authenticode.EvaluateAsync(path).GetAwaiter().GetResult().IsTrusted,
                pid => { using var p = System.Diagnostics.Process.GetProcessById(pid); p.Kill(); return true; },
                CoreGuard.Ipc.ProcessAncestry.ImagePath);
            _localExec.Blocked += b =>
            {
                _alerts.Publish(AlertSeverity.Critical, "Paranoïa", "Exécution bloquée",
                    $"{Path.GetFileName(b.ImagePath)} (non signé, lancé depuis {Path.GetDirectoryName(b.ImagePath)}) : " +
                    (b.Terminated ? "processus arrêté." : "arrêt impossible."));
                Set(Paranoia, ModuleState.Active, LocalParanoiaText());
                UiThread.Post(() => ModulesChanged?.Invoke());
            };
            _localExec.StartPolling(TimeSpan.FromMilliseconds(300));
            _alerts.Publish(AlertSeverity.Warning, "Paranoïa", "Mode Paranoïa activé (sans service)",
                "Exécutables non signés bloqués dans Téléchargements, %TEMP%, %APPDATA%. USB et pare-feu WFP : service CoreGuard requis.");
        }
        Set(Paranoia, ModuleState.Active, LocalParanoiaText());
    }

    private string LocalParanoiaText() =>
        $"Sans service : exécution non signée depuis les dossiers utilisateur bloquée ({_localExec?.BlockedCount ?? 0} arrêt(s)) ; USB et WFP : service requis";

    private bool StopLocalExec()
    {
        if (_localExec is null) return false;
        _localExec.Dispose();
        _localExec = null;
        return true;
    }

    private void SetParanoiaFromService() =>
        Set(Paranoia, _service.ParanoiaActive ? ModuleState.Active : ModuleState.Disabled,
            _service.ParanoiaActive ? "Service : " + (_service.ParanoiaText ?? "actif") : "Désactivé");

    private async Task EnableParanoiaViaServiceAsync()
    {
        if (Interlocked.Exchange(ref _paranoiaBusy, 1) == 1) return;
        try
        {
            var result = await _service.EnableParanoiaAsync();
            if (!result.Accepted)
            {
                _alerts.Publish(AlertSeverity.Warning, "Paranoïa", "Activation impossible", result.Message);
                UiThread.Post(() => { _settings.ParanoiaEnabled = false; _store.Save(_settings); });
            }
        }
        finally { Interlocked.Exchange(ref _paranoiaBusy, 0); }
    }

    // Thread UI : désactiver affaiblit la protection, le mot de passe de protection est demandé s'il est configuré
    private void DisableParanoiaViaService()
    {
        if (Interlocked.Exchange(ref _paranoiaBusy, 1) == 1) return;
        try
        {
            bool done;
            if (_service.StopPasswordConfigured)
            {
                done = _dialogs.AskPassword("Désactiver le Mode Paranoïa",
                    "Le Mode Paranoïa bloque l'USB, durcit le pare-feu et empêche les programmes non signés de se lancer depuis vos dossiers. " +
                    "Saisissez le mot de passe de protection CoreGuard pour le désactiver.", "Désactiver", _service.DisableParanoiaAsync);
            }
            else
            {
                var result = _service.DisableParanoiaAsync(null).GetAwaiter().GetResult();
                done = result.Accepted;
                if (!done) _alerts.Publish(AlertSeverity.Warning, "Paranoïa", "Désactivation refusée", result.Message);
            }
            if (!done) { _settings.ParanoiaEnabled = true; _store.Save(_settings); } // refus ou annulation : le mode reste actif
        }
        finally { Interlocked.Exchange(ref _paranoiaBusy, 0); }
    }

    // ---- Utilitaires ----
    private static void Stop<T>(ref T? holder, Action<T> stop) where T : class
    {
        if (holder is null) return;
        try { stop(holder); } catch { /* arrêt au mieux */ }
        holder = null;
    }

    private void Guard(ProtectionModule module, Action start)
    {
        try { start(); }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Set(module, ModuleState.Unavailable, $"Indisponible ({ex.GetType().Name})");
        }
    }

    private static void Set(ProtectionModule module, ModuleState state, string text) =>
        UiThread.Post(() => { module.State = state; module.StatusText = text; });

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _networkTimer?.Dispose();
            Stop(ref _files, f => f.Dispose());
            if (_canaries is not null) { try { _canaries.Remove(); _canaries.Dispose(); } catch { } _canaries = null; }
            Stop(ref _etw, m => m.Dispose());
            Stop(ref _persistence, p => p.Dispose());
            Stop(ref _clipboard, c => c.Dispose());
            Stop(ref _sensors, s => s.Dispose());
            Stop(ref _badUsb, m => m.Dispose());
            StopLocalExec();
        }
    }
}
