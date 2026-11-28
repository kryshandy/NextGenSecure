using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CoreGuard.Ipc;

namespace CoreGuard.Service;

/// <summary>Téléphone associé : clé d'appareil (256 bits) et port d'écoute. Fichier réservé à SYSTEM et aux Administrateurs.</summary>
public sealed record RemoteControlConfig(bool Enabled, int Port, string Key, DateTime PairedUtc)
{
    public const int DefaultPort = 8742;

    public static RemoteControlConfig CreateNew(int port = DefaultPort) =>
        new(true, port, Base64Url(RandomNumberGenerator.GetBytes(32)), DateTime.UtcNow);

    public byte[] KeyBytes => FromBase64Url(Key);

    public static RemoteControlConfig? Load(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<RemoteControlConfig>(File.ReadAllText(path)) : null; }
        catch (Exception ex) when (ex is IOException or JsonException) { return null; }
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(this));
        if (OperatingSystem.IsWindows())
        {
            var acl = new System.Security.AccessControl.FileSecurity();
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in new[] { System.Security.Principal.WellKnownSidType.LocalSystemSid, System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid })
                acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid, null),
                    System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(temp).SetAccessControl(acl);
        }
        File.Move(temp, path, overwrite: true);
    }

    /// <summary>Adresses à ouvrir sur le téléphone, une par adresse IPv4 locale (Wi-Fi, Ethernet, point d'accès 192.168.137.1).</summary>
    public IReadOnlyList<string> Urls() =>
        LocalAddresses().Select(ip => $"http://{ip}:{Port}/#k={Key}").ToList();

    public static IReadOnlyList<string> LocalAddresses() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a.Address)
                        && !a.Address.ToString().StartsWith("169.254.", StringComparison.Ordinal))
            .Select(a => a.Address.ToString())
            // Le point d'accès mobile de Windows en premier : c'est le cas « sans box, sans Internet »
            .OrderByDescending(ip => ip.StartsWith("192.168.137.", StringComparison.Ordinal))
            .Distinct().ToList();

    internal static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static byte[] FromBase64Url(string text)
    {
        string s = text.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}

/// <summary>
/// Authentification des ordres du téléphone (logique pure, testable) : défi à usage unique valable 60 s, signature
/// HMAC-SHA256(clé, « défi|action ») comparée en temps constant, verrouillage 5 minutes après 5 échecs.
/// </summary>
public sealed class RemoteControlAuth(byte[] key, Func<DateTime>? clock = null)
{
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan Lockout = TimeSpan.FromMinutes(5);
    public const int MaxFailures = 5;
    public static readonly string[] Actions = ["status", "lock", "unlock", "paranoia-on", "paranoia-off"];

    private readonly Func<DateTime> _now = clock ?? (() => DateTime.UtcNow);
    private readonly ConcurrentDictionary<string, DateTime> _challenges = new();
    private readonly object _gate = new();
    private int _failures;
    private DateTime _lockedUntil = DateTime.MinValue;

    public string IssueChallenge()
    {
        foreach (var (nonce, expiry) in _challenges) if (expiry < _now()) _challenges.TryRemove(nonce, out _);
        if (_challenges.Count > 100) _challenges.Clear(); // inondation : les défis en cours sont perdus, pas la sécurité
        string challenge = RemoteControlConfig.Base64Url(RandomNumberGenerator.GetBytes(16));
        _challenges[challenge] = _now() + ChallengeLifetime;
        return challenge;
    }

    public static string Sign(byte[] key, string challenge, string action) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(challenge + "|" + action)));

    /// <summary>Vérifie un ordre. Le défi est consommé même si la signature est fausse (aucun rejeu possible).</summary>
    public (bool Ok, string Message) Verify(string? challenge, string? action, string? mac)
    {
        lock (_gate)
        {
            if (_now() < _lockedUntil) return (false, "Trop d'échecs : réessayez dans quelques minutes.");
        }
        if (action is null || !Actions.Contains(action)) return Fail("Action inconnue.");
        if (challenge is null || !_challenges.TryRemove(challenge, out DateTime expiry) || expiry < _now()) return Fail("Défi expiré ou déjà utilisé.");
        if (mac is null || mac.Length != 64) return Fail("Signature invalide.");
        byte[] expected = Encoding.ASCII.GetBytes(Sign(key, challenge, action));
        if (!CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(mac.ToLowerInvariant()))) return Fail("Signature invalide (téléphone non associé ?).");
        lock (_gate) _failures = 0;
        return (true, "OK");
    }

    private (bool, string) Fail(string message)
    {
        lock (_gate)
        {
            if (++_failures >= MaxFailures) { _lockedUntil = _now() + Lockout; _failures = 0; }
        }
        return (false, message);
    }
}

/// <summary>
/// Petit serveur HTTP du service pour le téléphone (réseau local ou point d'accès mobile du PC, sans Internet) :
/// « / » sert la page de contrôle, « /api/challenge » donne un défi, « /api/command » exécute un ordre signé.
/// Requêtes bornées (8 Ko, 5 s), une connexion à la fois par client, aucune donnée secrète dans les réponses.
/// </summary>
public sealed class RemoteControlServer(
    RemoteControlConfig config,
    Func<string, (bool Ok, string Message)> execute,
    Func<object> status,
    Action<string, string, string, string> publish,
    ILogger logger) : IDisposable
{
    private const int MaxRequestBytes = 8 * 1024;
    private readonly RemoteControlAuth _auth = new(config.KeyBytes);
    private readonly CancellationTokenSource _cts = new();
    private TcpListener? _listener;

    public int Port => config.Port;

    public void Start()
    {
        _listener = new TcpListener(IPAddress.Any, config.Port);
        _listener.Start();
        _ = Task.Run(AcceptLoopAsync);
        logger.LogInformation("Contrôle à distance : écoute sur le port {Port}.", config.Port);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener!.AcceptTcpClientAsync(_cts.Token); }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException) { return; }
            _ = Task.Run(() => HandleAsync(client));
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                var stream = client.GetStream();
                var (method, path, body) = await ReadRequestAsync(stream, timeout.Token);
                string remote = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "?";
                var (code, type, content) = Route(method, path, body, remote);
                byte[] payload = Encoding.UTF8.GetBytes(content);
                string head = $"HTTP/1.1 {code}\r\nContent-Type: {type}; charset=utf-8\r\nContent-Length: {payload.Length}\r\n" +
                              "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n" +
                              "Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(head), timeout.Token);
                await stream.WriteAsync(payload, timeout.Token);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidDataException or SocketException)
            {
                // client parti, requête trop lente ou malformée
            }
        }
    }

    internal (string Code, string Type, string Content) Route(string method, string path, string body, string remote)
    {
        if (method == "GET" && (path == "/" || path.StartsWith("/?", StringComparison.Ordinal)))
            return ("200 OK", "text/html", RemotePage.Html);
        if (method == "POST" && path == "/api/challenge")
            return ("200 OK", "application/json", JsonSerializer.Serialize(new { challenge = _auth.IssueChallenge() }));
        if (method == "POST" && path == "/api/command")
        {
            string? challenge = null, action = null, mac = null;
            try
            {
                using var doc = JsonDocument.Parse(body);
                challenge = Str(doc.RootElement, "challenge");
                action = Str(doc.RootElement, "action");
                mac = Str(doc.RootElement, "mac");
            }
            catch (JsonException) { }
            var (ok, message) = _auth.Verify(challenge, action, mac);
            if (!ok)
            {
                publish("Warning", "Contrôle à distance", "Ordre refusé", $"{message} (depuis {remote})");
                return ("403 Forbidden", "application/json", JsonSerializer.Serialize(new { ok = false, message }));
            }
            if (action == "status")
                return ("200 OK", "application/json", JsonSerializer.Serialize(new { ok = true, message = "État lu.", status = status() }));
            var result = execute(action!);
            publish(result.Ok ? "Warning" : "Critical", "Contrôle à distance", result.Ok ? "Ordre exécuté depuis le téléphone" : "Ordre non exécuté",
                $"{action} : {result.Message} (depuis {remote})");
            return ("200 OK", "application/json", JsonSerializer.Serialize(new { ok = result.Ok, message = result.Message, status = status() }));
        }
        return ("404 Not Found", "text/plain", "Introuvable.");
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static async Task<(string Method, string Path, string Body)> ReadRequestAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[MaxRequestBytes];
        int read = 0, headerEnd = -1;
        while (headerEnd < 0)
        {
            if (read == buffer.Length) throw new InvalidDataException("En-têtes trop longs.");
            int n = await stream.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) throw new InvalidDataException("Connexion fermée.");
            read += n;
            headerEnd = IndexOf(buffer.AsSpan(0, read), "\r\n\r\n"u8);
        }
        string headers = Encoding.ASCII.GetString(buffer, 0, headerEnd);
        string[] lines = headers.Split("\r\n");
        string[] first = lines[0].Split(' ');
        if (first.Length < 2) throw new InvalidDataException("Requête invalide.");
        int length = 0;
        foreach (string line in lines.Skip(1))
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase) && int.TryParse(line[15..].Trim(), out int l)) length = l;
        if (length < 0 || headerEnd + 4 + length > MaxRequestBytes) throw new InvalidDataException("Requête trop volumineuse.");
        while (read < headerEnd + 4 + length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) break;
            read += n;
        }
        string body = Encoding.UTF8.GetString(buffer, headerEnd + 4, Math.Max(0, Math.Min(length, read - headerEnd - 4)));
        return (first[0], first[1], body);
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) => haystack.IndexOf(needle);

    public void Dispose()
    {
        _cts.Cancel();
        _listener?.Stop();
    }
}
