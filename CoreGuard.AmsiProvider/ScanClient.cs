using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace CoreGuard.AmsiProvider;

/// <summary>
/// Transmet le contenu au service CoreGuard (pipe local, même trame que CoreGuard.Ipc : longueur int32 + JSON)
/// et lit son verdict. Contraintes du contexte AMSI (code exécuté dans le processus PowerShell de l'utilisateur) :
/// - rapide : connexion 150 ms, réponse 800 ms au plus ; service injoignable → mémorisé 30 s (aucun délai ajouté) ;
/// - sûr : le serveur doit tourner en session 0 (un faux pipe créé par un programme utilisateur est ignoré) ;
/// - fail-open : toute erreur = « non détecté » (PowerShell reste utilisable si CoreGuard est arrêté).
/// JSON écrit et lu sans réflexion (Utf8JsonWriter / JsonDocument) : compatible NativeAOT.
/// </summary>
internal static partial class ScanClient
{
    private const string PipeName = "CoreGuard.Service.v1";
    private const string DevPipeName = "CoreGuard.Service.v1.dev";
    private const int ConnectTimeoutMs = 150;
    private const int ReplyTimeoutMs = 800;
    private const int MaxReplyBytes = 64 * 1024;
    private static readonly long UnavailableBackoffMs = 30_000;

    // Pipe injoignable : mémorisé pour ne pas ralentir chaque bloc de script (clé = nom du pipe)
    private static readonly object BackoffGate = new();
    private static string? s_unavailablePipe;
    private static long s_unavailableUntil;

    public static bool IsMalicious(string app, string? contentName, byte[] content)
    {
        // Développement uniquement : service lancé en console (pipe dédié, pas de contrôle de session)
        bool dev = Environment.GetEnvironmentVariable("COREGUARD_DEV_SERVICE") == "1";
        string pipeName = dev ? Environment.GetEnvironmentVariable("COREGUARD_AMSI_PIPE") ?? DevPipeName : PipeName;

        lock (BackoffGate)
            if (s_unavailablePipe == pipeName && Environment.TickCount64 < s_unavailableUntil) return false;

        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            pipe.Connect(ConnectTimeoutMs);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            lock (BackoffGate) { s_unavailablePipe = pipeName; s_unavailableUntil = Environment.TickCount64 + UnavailableBackoffMs; }
            return false;
        }

        if (!dev && !ServerIsService(pipe.SafePipeHandle)) return false;

        WriteFrame(pipe, BuildRequest(app, contentName, content));
        // Le service peut diffuser une alerte (voire son état) sur la même connexion AVANT le verdict : on lit les trames
        // jusqu'au verdict, dans le même budget de temps. Lire seulement la première laissait passer un script détecté.
        var reply = ReadVerdictAsync(pipe);
        if (!reply.Wait(ReplyTimeoutMs) || reply.Result is not { } body) return false;
        return ParseDetected(body);
    }

    private static async Task<byte[]?> ReadVerdictAsync(Stream stream)
    {
        for (int i = 0; i < 16; i++)
        {
            byte[]? body = await ReadFrameAsync(stream).ConfigureAwait(false);
            if (body is null) return null;
            if (IsVerdict(body)) return body;
        }
        return null;
    }

    /// <summary>Trame « amsiResult » (verdict) ? Les autres trames (alerte, état) sont ignorées.</summary>
    internal static bool IsVerdict(byte[] body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("type", out var type) && type.GetString() == "amsiResult";
        }
        catch (JsonException)
        {
            return false;
        }
    }

    internal static byte[] BuildRequest(string app, string? contentName, byte[] content)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteString("type", "amsiScan");
            w.WriteStartObject("amsi");
            w.WriteString("app", app);
            if (contentName is not null) w.WriteString("contentName", contentName);
            w.WriteBase64String("content", content);
            w.WriteEndObject();
            w.WriteEndObject();
        }
        return ms.ToArray();
    }

    /// <summary>Lit « amsiVerdict.detected » ; faux si la réponse n'est pas un verdict valide.</summary>
    internal static bool ParseDetected(byte[] body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            return root.TryGetProperty("type", out var type) && type.GetString() == "amsiResult"
                && root.TryGetProperty("amsiVerdict", out var verdict)
                && verdict.TryGetProperty("detected", out var detected)
                && detected.ValueKind == JsonValueKind.True;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static void WriteFrame(Stream stream, byte[] body)
    {
        byte[] frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame, 4);
        stream.Write(frame);
        stream.Flush();
    }

    private static async Task<byte[]?> ReadFrameAsync(Stream stream)
    {
        try
        {
            byte[] header = new byte[4];
            if (await stream.ReadAtLeastAsync(header, 4, throwOnEndOfStream: false).ConfigureAwait(false) < 4) return null;
            int length = BinaryPrimitives.ReadInt32LittleEndian(header);
            if (length <= 0 || length > MaxReplyBytes) return null;
            byte[] body = new byte[length];
            await stream.ReadExactlyAsync(body).ConfigureAwait(false);
            return body;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or EndOfStreamException)
        {
            return null;
        }
    }

    private static bool ServerIsService(SafePipeHandle pipe) =>
        GetNamedPipeServerProcessId(pipe, out uint pid) && pid != 0
        && ProcessIdToSessionId(pid, out uint session) && session == 0;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ProcessIdToSessionId(uint processId, out uint sessionId);
}
