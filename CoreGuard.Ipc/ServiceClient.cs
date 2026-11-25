using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CoreGuard.Ipc;

/// <summary>
/// Client du service CoreGuard. Avant d'accepter les données, il vérifie que le processus serveur tourne
/// en session 0 (réservée aux services Windows) : un programme utilisateur qui aurait créé un faux pipe
/// du même nom pour rassurer l'UI (« tout va bien ») est rejeté.
/// </summary>
public sealed partial class ServiceClient : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly bool _requireServiceSession;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private NamedPipeClientStream? _pipe;
    private CancellationTokenSource? _cts;
    private Task? _readLoop;

    /// <param name="requireServiceSession">
    /// true en production : le serveur doit être en session 0. false uniquement pour les tests et le
    /// développement (service lancé en console).
    /// </param>
    public ServiceClient(string pipeName = IpcContract.PipeName, bool requireServiceSession = true)
    {
        _pipeName = pipeName;
        _requireServiceSession = requireServiceSession;
    }

    public bool IsConnected => _pipe?.IsConnected == true;

    /// <summary>PID du processus serveur (0 si non connecté).</summary>
    public int ServerProcessId { get; private set; }

    public ServiceStatus? LastStatus { get; private set; }

    public event EventHandler<ServiceStatus>? StatusReceived;
    public event EventHandler<ServiceAlert>? AlertReceived;
    public event EventHandler? Disconnected;

    /// <summary>Se connecte et valide le serveur. Retourne false si le service est absent ou non authentique.</summary>
    public async Task<bool> ConnectAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        if (IsConnected) return true;
        await CloseAsync().ConfigureAwait(false);

        var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(timeout, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            return false;
        }

        if (!TryGetServerProcessId(pipe.SafePipeHandle, out int serverPid) || (_requireServiceSession && !IsServiceSession(serverPid)))
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            return false;
        }

        _pipe = pipe;
        ServerProcessId = serverPid;
        _cts = new CancellationTokenSource();
        _readLoop = Task.Run(() => ReadLoopAsync(pipe, _cts.Token));

        await SendAsync(new IpcEnvelope(IpcContract.Types.Hello, Version: IpcContract.ProtocolVersion)).ConfigureAwait(false);
        return true;
    }

    /// <summary>Demande l'état courant (réponse via <see cref="StatusReceived"/>).</summary>
    public Task RequestStatusAsync() => SendAsync(new IpcEnvelope(IpcContract.Types.GetStatus));

    internal Task SendRawAsync(IpcEnvelope message) => SendAsync(message);

    private async Task SendAsync(IpcEnvelope message)
    {
        var pipe = _pipe;
        if (pipe is null) return;
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await IpcContract.WriteAsync(pipe, message).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // La boucle de lecture signalera la déconnexion
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task ReadLoopAsync(NamedPipeClientStream pipe, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                IpcEnvelope? message = await IpcContract.ReadAsync(pipe, ct).ConfigureAwait(false);
                if (message is null) break;

                switch (message.Type)
                {
                    case IpcContract.Types.Status when message.Status is not null:
                        LastStatus = message.Status;
                        StatusReceived?.Invoke(this, message.Status);
                        break;
                    case IpcContract.Types.Alert when message.Alert is not null:
                        AlertReceived?.Invoke(this, message.Alert);
                        break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException or ObjectDisposedException)
        {
            // Service arrêté ou flux invalide
        }

        if (!ct.IsCancellationRequested)
        {
            LastStatus = null;
            Disconnected?.Invoke(this, EventArgs.Empty);
        }
    }

    private async Task CloseAsync()
    {
        _cts?.Cancel();
        if (_pipe is not null) await _pipe.DisposeAsync().ConfigureAwait(false);
        if (_readLoop is not null)
        {
            try { await _readLoop.ConfigureAwait(false); } catch { /* fermeture */ }
        }
        _cts?.Dispose();
        _cts = null;
        _pipe = null;
        _readLoop = null;
        ServerProcessId = 0;
        LastStatus = null;
    }

    public async ValueTask DisposeAsync() => await CloseAsync().ConfigureAwait(false);

    // ---------- Vérification du serveur ----------

    private static bool TryGetServerProcessId(SafePipeHandle pipe, out int pid)
    {
        bool ok = GetNamedPipeServerProcessId(pipe, out uint id);
        pid = (int)id;
        return ok && id != 0;
    }

    /// <summary>Vrai si le processus tourne en session 0 (services Windows uniquement).</summary>
    internal static bool IsServiceSession(int pid) => ProcessIdToSessionId((uint)pid, out uint session) && session == 0;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ProcessIdToSessionId(uint processId, out uint sessionId);
}
