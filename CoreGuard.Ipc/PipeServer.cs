using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CoreGuard.Ipc;

/// <summary>
/// Serveur du canal UI ↔ service : accepte jusqu'à <see cref="MaxClients"/> clients, répond aux demandes
/// d'état et diffuse les alertes à tous les clients connectés. Un client fautif est déconnecté sans
/// affecter les autres ni le service.
/// </summary>
public sealed partial class PipeServer : IAsyncDisposable
{
    public const int MaxClients = 8;

    private readonly string _pipeName;
    private readonly Func<ServiceStatus> _status;
    private readonly PipeSecurity? _security;
    private readonly Func<IpcEnvelope, IpcEnvelope?>? _commands;
    private readonly ConcurrentDictionary<Guid, ClientConnection> _clients = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;

    /// <param name="security">ACL du pipe ; null = ACL par défaut (tests). Voir <see cref="CreateServiceSecurity"/>.</param>
    /// <param name="commands">
    /// Traitement des demandes autres que l'état (défi et demande d'arrêt) ; null = canal en lecture seule.
    /// Renvoyer null refuse la demande.
    /// </param>
    public PipeServer(string pipeName, Func<ServiceStatus> status, PipeSecurity? security,
        Func<IpcEnvelope, IpcEnvelope?>? commands = null)
    {
        _pipeName = pipeName;
        _status = status;
        _security = security;
        _commands = commands;
    }

    public int ClientCount => _clients.Count;

    /// <summary>Levé quand une instance de pipe n'a pas pu être créée (ex. nom déjà pris par un autre processus).</summary>
    public event EventHandler<Exception>? Error;

    /// <summary>Levé à chaque connexion (PID du client) : journalisation côté service.</summary>
    public event EventHandler<int>? ClientConnected;

    /// <summary>
    /// ACL du pipe du service : SYSTEM, Administrateurs et le compte du serveur en contrôle total, utilisateurs
    /// interactifs en lecture/écriture (l'UI de la session), accès réseau refusé (pipe strictement local).
    /// </summary>
    public static PipeSecurity CreateServiceSecurity()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        // Compte qui exécute le serveur (SYSTEM en production) : droit de créer les instances suivantes du pipe
        if (WindowsIdentity.GetCurrent().User is { } self)
            security.AddAccessRule(new PipeAccessRule(self, PipeAccessRights.FullControl, AccessControlType.Allow));
        return security;
    }

    public void Start()
    {
        _acceptLoop ??= Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    /// <summary>Diffuse une alerte à tous les clients connectés (sans bloquer l'appelant sur un client lent).</summary>
    public void Broadcast(ServiceAlert alert) => BroadcastEnvelope(new IpcEnvelope(IpcContract.Types.Alert, Alert: alert));

    /// <summary>Pousse l'état courant à tous les clients (après un changement d'état d'un module).</summary>
    public void BroadcastStatus() => BroadcastEnvelope(new IpcEnvelope(IpcContract.Types.Status, Status: SafeStatus()));

    private void BroadcastEnvelope(IpcEnvelope message)
    {
        foreach (var client in _clients.Values)
            _ = client.SendAsync(message);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        bool first = true;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = CreatePipe(first);
                first = false;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Nom déjà réservé (squattage par un autre processus ?) ou trop d'instances : on réessaie plus tard
                Error?.Invoke(this, ex);
                try { await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false); } catch (OperationCanceledException) { return; }
                continue;
            }

            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                if (ct.IsCancellationRequested) return;
                continue;
            }

            if (_clients.Count >= MaxClients)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            var client = new ClientConnection(pipe);
            _clients[client.Id] = client;
            if (GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint clientPid))
                ClientConnected?.Invoke(this, (int)clientPid);
            _ = Task.Run(() => ServeAsync(client, ct));
        }
    }

    private NamedPipeServerStream CreatePipe(bool firstInstance)
    {
        // FirstPipeInstance : si un autre processus a déjà créé ce nom, la création échoue au lieu de se joindre à lui
        var options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return _security is null
            ? new NamedPipeServerStream(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, options)
            : NamedPipeServerStreamAcl.Create(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, options, 0, 0, _security);
    }

    private async Task ServeAsync(ClientConnection client, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                IpcEnvelope? message = await IpcContract.ReadAsync(client.Stream, ct).ConfigureAwait(false);
                if (message is null) break;

                IpcEnvelope reply = message.Type switch
                {
                    IpcContract.Types.Hello or IpcContract.Types.GetStatus =>
                        new IpcEnvelope(IpcContract.Types.Status, Status: SafeStatus(), Version: IpcContract.ProtocolVersion),
                    IpcContract.Types.Challenge or IpcContract.Types.StopRequest or IpcContract.Types.AmsiScan =>
                        SafeCommand(message) ?? new IpcEnvelope(IpcContract.Types.Error, Error: "Requête refusée."),
                    // Toute autre demande est refusée
                    _ => new IpcEnvelope(IpcContract.Types.Error, Error: "Requête non prise en charge.")
                };
                await client.SendAsync(reply).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException or ObjectDisposedException)
        {
            // Client déconnecté ou trame invalide : on ferme cette connexion uniquement
        }
        finally
        {
            _clients.TryRemove(client.Id, out _);
            await client.DisposeAsync().ConfigureAwait(false);
        }
    }

    private IpcEnvelope? SafeCommand(IpcEnvelope message)
    {
        if (_commands is null) return null;
        try { return _commands(message); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return null; }
    }

    private ServiceStatus SafeStatus()
    {
        try { return _status(); }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new ServiceStatus(IpcContract.ProtocolVersion, Environment.ProcessId, DateTime.UtcNow,
                "?", false, false, [new ModuleStatus("Service", "Unavailable", "État indisponible")]);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.ConfigureAwait(false); } catch { /* arrêt */ }
        }
        foreach (var c in _clients.Values) await c.DisposeAsync().ConfigureAwait(false);
        _clients.Clear();
        _cts.Dispose();
    }

    [System.Runtime.InteropServices.LibraryImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint clientProcessId);

    private sealed class ClientConnection(NamedPipeServerStream stream) : IAsyncDisposable
    {
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        public Guid Id { get; } = Guid.NewGuid();
        public NamedPipeServerStream Stream { get; } = stream;

        public async Task SendAsync(IpcEnvelope message)
        {
            if (!await _writeLock.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false)) return; // client trop lent : message perdu
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await IpcContract.WriteAsync(Stream, message, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
                // Le lecteur détectera la déconnexion
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async ValueTask DisposeAsync()
        {
            try { await Stream.DisposeAsync().ConfigureAwait(false); } catch { /* déjà fermé */ }
        }
    }
}
