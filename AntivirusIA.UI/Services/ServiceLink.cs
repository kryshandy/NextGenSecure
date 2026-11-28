using AntivirusIA.UI.Models;
using CoreGuard.Ipc;

namespace AntivirusIA.UI.Services;

/// <summary>
/// Lien entre l'UI et le service CoreGuard (SYSTEM). Se (re)connecte en arrière-plan, relaie les alertes
/// du service dans le flux d'alertes et indique quels modules le service assure, pour que l'UI ne les
/// démarre pas une seconde fois. Sans service, l'UI garde son fonctionnement autonome.
/// </summary>
public sealed class ServiceLink : IDisposable
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(10);

    private readonly AlertHub _alerts;
    private readonly ServiceClient _client;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;
    private ServiceStatus? _status;

    public ServiceLink(AlertHub alerts)
    {
        _alerts = alerts;
        // Mode développement : pipe dédié du service lancé en console (jamais celui du service installé)
        _client = DevServiceAllowed
            ? new ServiceClient(IpcContract.DevPipeName, requireServiceSession: false)
            : new ServiceClient(IpcContract.PipeName, requireServiceSession: true);
        _client.StatusReceived += (_, s) => { _status = s; StatusChanged?.Invoke(); };
        _client.AlertReceived += (_, a) => _alerts.Publish(MapSeverity(a.Severity), "Service · " + a.Source, a.Title, a.Detail);
        _client.Disconnected += (_, _) =>
        {
            _status = null;
            _alerts.Publish(AlertSeverity.Warning, "Service", "Service CoreGuard déconnecté",
                "La protection système (ETW) repasse en mode local tant que le service est absent.");
            StatusChanged?.Invoke();
        };
    }

    /// <summary>
    /// Service lancé en console (développement) accepté hors session 0 : uniquement en Debug et
    /// avec COREGUARD_DEV_SERVICE=1. En Release, seul un vrai service Windows est accepté.
    /// </summary>
    private static bool DevServiceAllowed
    {
        get
        {
#if DEBUG
            return Environment.GetEnvironmentVariable("COREGUARD_DEV_SERVICE") == "1";
#else
            return false;
#endif
        }
    }

    public bool IsConnected => _client.IsConnected && _status is not null;

    public ServiceStatus? Status => _status;

    /// <summary>Vrai si le service assure lui-même la télémétrie ETW des processus.</summary>
    public bool HandlesBehavior => IsConnected && _status!.IsModuleActive(ServiceModules.Behavior);

    /// <summary>Verrouillage d'urgence actif (selon le service).</summary>
    public bool LockdownEngaged => IsConnected && _status!.IsModuleActive(ServiceModules.Lockdown);

    /// <summary>Texte d'état du verrouillage (motif, heure ; ou état du déclenchement à distance).</summary>
    public string? LockdownText => _status?.Modules.FirstOrDefault(m => m.Name == ServiceModules.Lockdown)?.Text;

    public Task<StopResult> EngageLockdownAsync(string reason, bool cutNetwork) => _client.EngageLockdownAsync(reason, cutNetwork);

    public Task<StopResult> RequestUnlockAsync(string password) => _client.RequestUnlockAsync(password);

    /// <summary>Vrai si le service connecté sait appliquer le Mode Paranoïa (USB, WFP, blocage d'exécution).</summary>
    public bool HandlesParanoia => IsConnected && _status!.Modules.Any(m => m.Name == ServiceModules.Paranoia && m.State != "Unavailable");

    public bool ParanoiaActive => IsConnected && _status!.IsModuleActive(ServiceModules.Paranoia);

    public string? ParanoiaText => _status?.Modules.FirstOrDefault(m => m.Name == ServiceModules.Paranoia)?.Text;

    public bool StopPasswordConfigured => _status?.StopPasswordConfigured ?? false;

    public Task<StopResult> EnableParanoiaAsync() => _client.EnableParanoiaAsync();

    /// <summary>État du contrôle à distance par téléphone (texte du service), null si inconnu.</summary>
    public string? RemoteText => _status?.Modules.FirstOrDefault(m => m.Name == ServiceModules.Remote)?.Text;

    public bool RemoteActive => IsConnected && _status!.IsModuleActive(ServiceModules.Remote);

    /// <summary>Associe un téléphone (nouvelle clé) ou révoque l'association ; mot de passe de protection requis.</summary>
    public Task<RemotePairing> RemoteAsync(bool pair, string password) => _client.RemoteAsync(pair, password);

    public Task<StopResult> DisableParanoiaAsync(string? password) => _client.DisableParanoiaAsync(password);

    /// <summary>Vrai si le service assure les canaris anti-ransomware.</summary>
    public bool HandlesCanaries => IsConnected && _status!.IsModuleActive(ServiceModules.Canaries);

    /// <summary>Texte d'état des canaris côté service (null si non connecté).</summary>
    public string? CanariesText => _status?.Modules.FirstOrDefault(m => m.Name == ServiceModules.Canaries)?.Text;

    /// <summary>
    /// Vrai si le service CoreGuard est installé (ou si le mode développement est actif). Dans ce cas, l'UI ne
    /// dépose jamais ses propres canaris : deux gestionnaires sur les mêmes fichiers se prendraient mutuellement
    /// pour un ransomware.
    /// </summary>
    public static bool ServiceInstalled
    {
        get
        {
            if (DevServiceAllowed) return true;
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\CoreGuardService");
                return key is not null;
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    /// <summary>Vrai si l'auto-défense du service (DACL durcie + watchdog) est active.</summary>
    public bool SelfDefenseActive => IsConnected && _status!.IsModuleActive(ServiceModules.SelfDefense);

    /// <summary>Demande l'arrêt authentifié du service (le mot de passe ne quitte pas ce processus).</summary>
    public Task<StopResult> RequestStopAsync(string password) => _client.RequestStopAsync(password);

    /// <summary>Levé (thread quelconque) quand la connexion ou l'état du service change.</summary>
    public event Action? StatusChanged;

    public void Start() => _loop ??= Task.Run(() => ConnectLoopAsync(_cts.Token));

    private async Task ConnectLoopAsync(CancellationToken ct)
    {
        bool announced = false;
        while (!ct.IsCancellationRequested)
        {
            if (!_client.IsConnected)
            {
                bool ok = await _client.ConnectAsync(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                if (ok)
                {
                    _alerts.Publish(AlertSeverity.Info, "Service", "Connecté au service CoreGuard",
                        $"PID {_client.ServerProcessId}{(DevServiceAllowed ? " (mode développement)" : "")}");
                    announced = true;
                }
                else if (!announced)
                {
                    announced = true; // une seule mention au démarrage, pas une alerte toutes les 10 s
                    _alerts.Publish(AlertSeverity.Info, "Service", "Service CoreGuard absent",
                        "Fonctionnement autonome : installez le service (scripts/install-service.ps1) pour la protection système.");
                }
            }

            try { await Task.Delay(RetryDelay, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    private static AlertSeverity MapSeverity(string severity) => severity switch
    {
        "Critical" => AlertSeverity.Critical,
        "Warning" => AlertSeverity.Warning,
        _ => AlertSeverity.Info
    };

    // IDisposable (et non IAsyncDisposable) : le conteneur DI est libéré de façon synchrone à la fermeture
    public void Dispose()
    {
        _cts.Cancel();
        try { _client.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(2)); } catch { /* arrêt au mieux */ }
        _cts.Dispose();
    }
}
