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

    public ObservableCollection<ProtectionModule> Modules { get; }

    /// <summary>Levé (thread UI) quand l'état d'un module a changé.</summary>
    public event Action? ModulesChanged;

    private readonly ServiceLink _service;

    public ProtectionService(AppSettings settings, AlertHub alerts, ScanService scan, UiThreatResponder responder, INetworkGuard network,
        ServiceLink service)
    {
        _settings = settings;
        _alerts = alerts;
        _scan = scan;
        _responder = responder;
        _network = network;
        _service = service;
        Modules = [Files, Canaries, Behavior, Persistence, Network, Clipboard, Sensors, Paranoia];

        // Le service (SYSTEM) prend la télémétrie ETW dès qu'il est joignable, et la rend s'il disparaît
        _service.StatusChanged += () => _ = ApplyServiceModulesAsync();
    }

    public int ActiveCount => Modules.Count(m => m.State == ModuleState.Active);

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
            ApplyParanoia();
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
            Set(Files, ModuleState.Active, "Téléchargements surveillés");
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
                await _scan.ScanFileAsync(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException)
            {
                // Fichier déjà supprimé ou verrouillé : rien à faire
            }
            finally { _downloadScanLock.Release(); }
        });
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
            watcher.PersistenceDetected += (_, e) => _alerts.Publish(
                AlertSeverity.Warning, "Persistance", $"Nouvelle persistance : {e.Kind}", $"{e.Target} -> {e.Command}");
            watcher.Start();
            _persistence = watcher;
            Set(Persistence, ModuleState.Active, "Registre et tâches surveillés");
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
                if (u.InUse)
                    _alerts.Publish(AlertSeverity.Warning, "Vie privée", $"{u.Sensor} utilisé", Path.GetFileName(u.Process));
            };
            monitor.Start();
            _sensors = monitor;
            Set(Sensors, ModuleState.Active, "Webcam et micro surveillés");
        });
    }

    private void ApplyParanoia()
    {
        bool changed = _paranoia.SetEnabled(_settings.ParanoiaEnabled);
        if (changed)
            _alerts.Publish(AlertSeverity.Info, "Paranoïa", _settings.ParanoiaEnabled ? "Mode paranoïa activé" : "Mode paranoïa désactivé",
                "Politique de durcissement mise à jour (application réelle déléguée à la couche service)");
        Set(Paranoia, _settings.ParanoiaEnabled ? ModuleState.Active : ModuleState.Disabled,
            _settings.ParanoiaEnabled ? "Politique stricte" : "Désactivé");
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
        }
    }
}
