using System.Collections.Concurrent;
using System.Runtime.Versioning;
using AntivirusIA.Core.Interfaces;
using CoreGuard.RealTime;

namespace CoreGuard.Service;

/// <summary>
/// Anti-ransomware du service : canaris cachés dans les dossiers de chaque utilisateur, restauration immédiate,
/// et ARRÊT du processus coupable lorsque l'audit NTFS l'identifie avec certitude (PID exact de l'événement 4663).
/// Sans audit (stratégie désactivée, droits insuffisants), aucun processus n'est arrêté : alerte et restauration
/// seules — jamais d'arrêt sur une supposition.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CanaryGuard : IDisposable
{
    private static readonly TimeSpan FolderRefresh = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan KillDedup = TimeSpan.FromSeconds(30);

    private readonly IKernelActionProvider _actions;
    private readonly Action<string, string, string, string> _publish; // sévérité, source, titre, détail
    private readonly ILogger _logger;
    private readonly HashSet<string> _folders = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, DateTime> _killed = new();
    private readonly object _gate = new();
    private CanaryManager? _manager;
    private CanaryAuditWatcher? _audit;
    private Timer? _refresh;
    private bool _auditReady = true;

    public CanaryGuard(IKernelActionProvider actions, Action<string, string, string, string> publish, ILogger logger)
    {
        _actions = actions;
        _publish = publish;
        _logger = logger;
    }

    /// <summary>Vrai si les écritures sur les canaris sont attribuées par l'audit (arrêt du processus possible).</summary>
    public bool AttributionActive { get; private set; }

    public int CanaryCount => _manager?.CanaryPaths.Count ?? 0;

    /// <summary>Texte d'état pour l'UI.</summary>
    public string StatusText => CanaryCount == 0
        ? "Aucun dossier utilisateur accessible"
        : AttributionActive
            ? $"{CanaryCount} leurres, attribution par audit NTFS : arrêt du processus coupable"
            : $"{CanaryCount} leurres, audit indisponible : alerte et restauration seules";

    public void Start()
    {
        var manager = new CanaryManager(new Responder(this), pidResolver: () => null);
        manager.Warning += (_, w) => _logger.LogWarning("{Warning}", w);
        manager.CanaryWritten += (_, path) => ApplyAudit(path); // un canari recréé perd sa SACL : on la repose
        _manager = manager;

        bool? policy = CanaryAuditWatcher.IsFileSystemAuditEnabled();
        var audit = new CanaryAuditWatcher(manager.IsCanary);
        audit.Warning += (_, w) => _logger.LogWarning("{Warning}", w);
        audit.Access += (_, a) => OnAudited(a);
        bool listening = audit.Start();
        _audit = listening ? audit : null;
        if (!listening) audit.Dispose();

        DeployNewFolders();
        AttributionActive = listening && _auditReady && policy != false;
        if (policy == false)
            _logger.LogWarning("Audit « Système de fichiers » désactivé : lancez scripts/install-service.ps1 (auditpol) pour l'arrêt automatique.");

        _refresh = new Timer(_ => DeployNewFolders(), null, FolderRefresh, FolderRefresh);
    }

    // Nouveaux profils / utilisateur connecté depuis : dépôt dans les dossiers pas encore protégés
    private void DeployNewFolders()
    {
        var manager = _manager;
        if (manager is null) return;
        IReadOnlyList<string> folders = ServiceHost.IsWindowsService ? UserProfiles.CanaryFolders() : CanaryManager.DefaultFolders().ToList();

        List<string> fresh;
        lock (_gate) fresh = folders.Where(f => _folders.Add(f)).ToList();
        if (fresh.Count == 0) return;

        var created = manager.Deploy(fresh);
        _logger.LogInformation("{Count} canaris déposés dans {Folders} dossier(s).", created.Count, fresh.Count);
    }

    private void ApplyAudit(string path)
    {
        if (!CanaryAuditWatcher.TryEnableAudit(path, out string? error))
        {
            if (_auditReady) _logger.LogWarning("Audit NTFS impossible sur les canaris ({Error}) : arrêt automatique désactivé.", error);
            _auditReady = false;
            AttributionActive = false;
        }
    }

    private void OnAudited(CanaryAccess access)
    {
        if (access.Pid == Environment.ProcessId) return; // nos propres dépôts / restaurations

        DateTime now = DateTime.UtcNow;
        if (_killed.TryGetValue(access.Pid, out DateTime last) && now - last < KillDedup) return;
        _killed[access.Pid] = now;

        string image = Path.GetFileName(access.ProcessName);
        _ = Task.Run(async () =>
        {
            ActionResult result = await _actions.TerminateProcessAsync(access.Pid,
                $"écriture sur le fichier leurre {Path.GetFileName(access.Path)} (comportement de ransomware)");
            _publish(result.Success ? "Critical" : "Warning", "Anti-ransomware",
                result.Success ? $"Ransomware arrêté : {image}" : $"Arrêt impossible : {image}",
                $"{image} (PID {access.Pid}) a modifié {Path.GetFileName(access.Path)}. {result.Message}");
            _logger.LogWarning("Canari {Path} modifié par {Image} (PID {Pid}) : {Message}", access.Path, image, access.Pid, result.Message);
        });
    }

    public void Dispose()
    {
        _refresh?.Dispose();
        _audit?.Dispose();
        if (_manager is not null)
        {
            try { _manager.Remove(); } catch { /* best-effort */ }
            _manager.Dispose();
        }
        _manager = null;
    }

    // Alerte de détection par le watcher (le canari est restauré automatiquement par CanaryManager)
    private sealed class Responder(CanaryGuard owner) : IThreatResponder
    {
        public Task OnCanaryTriggeredAsync(CanaryAlert alert, CancellationToken ct)
        {
            owner._logger.LogWarning("Canari {Path} touché ({Operation}) : restauration.", alert.CanaryPath, alert.OperationType);
            owner._publish("Critical", "Anti-ransomware", $"Fichier leurre {alert.OperationType}",
                $"{Path.GetFileName(alert.CanaryPath)} restauré depuis sa copie chiffrée en mémoire"
                + (owner.AttributionActive ? "." : " (audit indisponible : processus non identifié, aucun arrêt)."));
            return Task.CompletedTask;
        }

        public Task KillProcessAsync(int pid) => Task.CompletedTask;
        public Task QuarantineAsync(string path, string reason) => Task.CompletedTask;
    }
}
