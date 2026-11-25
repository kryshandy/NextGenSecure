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
        _client = new ServiceClient(IpcContract.PipeName, requireServiceSession: !DevServiceAllowed);
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
