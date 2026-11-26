using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace CoreGuard.Ipc;

/// <summary>Réponse du coffre à une demande d'identifiant.</summary>
public sealed record CredentialLookup(bool Found, string? Username, string? Password, bool Locked, bool Denied = false)
{
    public static readonly CredentialLookup NotFound = new(false, null, null, false);
    public static readonly CredentialLookup VaultLocked = new(false, null, null, true);
    public static readonly CredentialLookup AccessDenied = new(false, null, null, false, Denied: true);
}

internal sealed record VaultRequest(string Type, string? Url);

/// <summary>
/// Canal entre l'interface (qui détient le coffre déverrouillé) et l'hôte Native Messaging du navigateur.
/// - Pipe propre à l'utilisateur (« CoreGuard.Vault.&lt;SID&gt; »), ACL : ce compte uniquement, réseau refusé.
/// - Le serveur identifie le processus client (<c>GetNamedPipeClientProcessId</c>) et le soumet à
///   <c>authorize</c> : l'interface n'accepte que l'hôte CoreGuard lancé par un navigateur signé. Un programme
///   malveillant du même utilisateur qui se connecterait directement reçoit « refusé ».
/// - Une seule demande par connexion, trames bornées (16 Ko).
/// </summary>
public static partial class VaultBroker
{
    private const int MaxMessageBytes = 16 * 1024;

    public static string PipeName =>
        "CoreGuard.Vault." + (WindowsIdentity.GetCurrent().User?.Value ?? "inconnu");

    // ---------------------------------------------------------------- Serveur (interface)

    /// <summary>
    /// Sert les demandes jusqu'à annulation. <paramref name="lookup"/> cherche l'identifiant d'une URL ;
    /// <paramref name="authorize"/> reçoit le PID du client et décide s'il a le droit de demander.
    /// </summary>
    public static async Task ServeAsync(Func<string, Task<CredentialLookup>> lookup, Func<int, bool> authorize,
        CancellationToken ct, string? pipeName = null)
    {
        string name = pipeName ?? PipeName;
        var security = new PipeSecurity();
        var self = WindowsIdentity.GetCurrent().User!;
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(self, PipeAccessRights.FullControl, AccessControlType.Allow));

        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                try { await Task.Delay(2000, ct).ConfigureAwait(false); } catch (OperationCanceledException) { return; }
                continue;
            }

            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                if (ct.IsCancellationRequested) return;
                continue;
            }

            _ = Task.Run(() => HandleAsync(pipe, lookup, authorize, ct), ct);
        }
    }

    private static async Task HandleAsync(NamedPipeServerStream pipe, Func<string, Task<CredentialLookup>> lookup,
        Func<int, bool> authorize, CancellationToken ct)
    {
        await using (pipe)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));

                byte[]? body = await ReadFrameAsync(pipe, timeout.Token).ConfigureAwait(false);
                if (body is null) return;

                CredentialLookup result;
                bool allowed = GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint pid) && SafeAuthorize(authorize, (int)pid);
                if (!allowed)
                {
                    result = CredentialLookup.AccessDenied;
                }
                else
                {
                    var request = JsonSerializer.Deserialize<VaultRequest>(body, IpcContract.Json);
                    result = request is { Type: "find", Url: { Length: > 0 and < 2048 } url }
                        ? await lookup(url).ConfigureAwait(false)
                        : CredentialLookup.NotFound;
                }
                await WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(result, IpcContract.Json), timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or JsonException or OperationCanceledException or ObjectDisposedException)
            {
                // client parti ou trame invalide
            }
        }
    }

    private static bool SafeAuthorize(Func<int, bool> authorize, int pid)
    {
        try { return authorize(pid); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return false; }
    }

    // ---------------------------------------------------------------- Client (hôte du navigateur)

    /// <summary>Demande l'identifiant d'une URL au coffre. Coffre injoignable (interface fermée) → « verrouillé ».</summary>
    public static async Task<CredentialLookup> FindAsync(string url, CancellationToken ct = default, string? pipeName = null)
    {
        await using var pipe = new NamedPipeClientStream(".", pipeName ?? PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(TimeSpan.FromMilliseconds(500), ct).ConfigureAwait(false);
            await WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(new VaultRequest("find", url), IpcContract.Json), ct).ConfigureAwait(false);
            byte[]? body = await ReadFrameAsync(pipe, ct).ConfigureAwait(false);
            return body is null ? CredentialLookup.VaultLocked
                : JsonSerializer.Deserialize<CredentialLookup>(body, IpcContract.Json) ?? CredentialLookup.NotFound;
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException or JsonException)
        {
            return CredentialLookup.VaultLocked;
        }
    }

    /// <summary>
    /// L'identifiant enregistré pour <paramref name="entryUrl"/> vaut-il pour la page <paramref name="pageHost"/> ?
    /// Hôte identique, ou sous-domaine de l'hôte enregistré (www.banque.fr pour banque.fr) ; jamais l'inverse,
    /// ni un domaine qui se contente de contenir le nom (banque.fr.evil.net).
    /// </summary>
    public static bool MatchesHost(string entryUrl, string pageHost)
    {
        string? entryHost = Uri.TryCreate(entryUrl, UriKind.Absolute, out var u) ? u.Host
            : Uri.TryCreate("https://" + entryUrl, UriKind.Absolute, out var u2) ? u2.Host : null;
        if (string.IsNullOrEmpty(entryHost) || string.IsNullOrEmpty(pageHost)) return false;
        return pageHost.Equals(entryHost, StringComparison.OrdinalIgnoreCase)
            || pageHost.EndsWith("." + entryHost, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------- Trames

    private static async Task WriteFrameAsync(Stream stream, byte[] body, CancellationToken ct)
    {
        if (body.Length > MaxMessageBytes) throw new InvalidDataException("Message trop volumineux.");
        byte[] frame = new byte[4 + body.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame, 4);
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadFrameAsync(Stream stream, CancellationToken ct)
    {
        byte[] header = new byte[4];
        if (await stream.ReadAtLeastAsync(header, 4, throwOnEndOfStream: false, ct).ConfigureAwait(false) < 4) return null;
        int length = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaxMessageBytes) return null;
        byte[] body = new byte[length];
        await stream.ReadExactlyAsync(body, ct).ConfigureAwait(false);
        return body;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);
}

/// <summary>
/// Ascendance d'un processus (parent, grand-parent…) via un instantané Toolhelp. Sert à vérifier que l'hôte
/// Native Messaging a bien été lancé par le navigateur (Chrome le lance via « cmd.exe /d /c » sous Windows).
/// </summary>
public static partial class ProcessAncestry
{
    /// <summary>PID des ascendants de <paramref name="pid"/>, du parent vers la racine (au plus <paramref name="depth"/>).</summary>
    public static IReadOnlyList<int> Ancestors(int pid, int depth = 4)
    {
        var parents = new Dictionary<int, int>();
        IntPtr snapshot = CreateToolhelp32Snapshot(0x2 /* TH32CS_SNAPPROCESS */, 0);
        if (snapshot == new IntPtr(-1)) return [];
        try
        {
            var entry = new ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (Process32FirstW(snapshot, ref entry))
            {
                do { parents[(int)entry.th32ProcessID] = (int)entry.th32ParentProcessID; }
                while (Process32NextW(snapshot, ref entry));
            }
        }
        finally
        {
            CloseHandle(snapshot);
        }

        var result = new List<int>();
        int current = pid;
        for (int i = 0; i < depth && parents.TryGetValue(current, out int parent) && parent > 4 && !result.Contains(parent); i++)
        {
            result.Add(parent);
            current = parent;
        }
        return result;
    }

    /// <summary>Chemin complet de l'exécutable d'un processus, ou null.</summary>
    public static string? ImagePath(int pid)
    {
        using SafeProcessHandle h = OpenProcess(0x1000 /* QUERY_LIMITED_INFORMATION */, false, pid);
        if (h.IsInvalid) return null;
        var buffer = new char[1024];
        uint size = (uint)buffer.Length;
        return QueryFullProcessImageNameW(h, 0, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] buffer, ref uint size);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
