using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CoreGuard.Ipc;

/// <summary>
/// Contrat du canal UI ↔ service (named pipe local). Le client peut demander l'état et reçoit les alertes.
/// Deux demandes seulement sont acceptées en plus : l'analyse d'un contenu soumis par le fournisseur AMSI
/// (qui ne fait que renvoyer un verdict) et l'arrêt de la protection, uniquement après un défi-réponse HMAC
/// prouvant la connaissance du mot de passe de protection (<see cref="StopAuthenticator"/>). Aucune autre
/// action (arrêt d'un processus tiers, désactivation d'un module…) n'est exposée : un programme
/// malveillant connecté au pipe ne peut pas utiliser le service SYSTEM pour agir à sa place.
/// Trame : longueur (int32 little-endian) puis JSON UTF-8, au plus <see cref="MaxMessageBytes"/> octets.
/// </summary>
public static class IpcContract
{
    public const string PipeName = "CoreGuard.Service.v1";

    /// <summary>Pipe du service lancé en console (développement) : ne se confond jamais avec le service installé.</summary>
    public const string DevPipeName = "CoreGuard.Service.v1.dev";
    public const int ProtocolVersion = 1;
    // 1 Mo : un bloc de script analysé par AMSI peut dépasser 64 Ko (le contenu est plafonné à 512 Ko côté fournisseur)
    public const int MaxMessageBytes = 1024 * 1024;

    public static class Types
    {
        public const string Hello = "hello";
        public const string GetStatus = "getStatus";
        public const string Status = "status";
        public const string Alert = "alert";
        public const string Error = "error";
        public const string Challenge = "challenge";
        public const string StopRequest = "stopRequest";
        public const string StopResult = "stopResult";
        public const string AmsiScan = "amsiScan";
        public const string AmsiResult = "amsiResult";
    }

    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static async Task WriteAsync(Stream stream, IpcEnvelope message, CancellationToken ct = default)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(message, Json);
        if (body.Length > MaxMessageBytes) throw new InvalidDataException("Message IPC trop volumineux.");

        byte[] frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame, 4);
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Lit un message ; null si le flux est fermé proprement. Lève <see cref="InvalidDataException"/> si la trame est invalide.</summary>
    public static async Task<IpcEnvelope?> ReadAsync(Stream stream, CancellationToken ct = default)
    {
        byte[] header = new byte[4];
        int read = await stream.ReadAtLeastAsync(header, 4, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        if (read == 0) return null;
        if (read < 4) throw new InvalidDataException("En-tête IPC tronqué.");

        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaxMessageBytes) throw new InvalidDataException($"Taille de message IPC invalide ({length}).");

        byte[] body = new byte[length];
        await stream.ReadExactlyAsync(body, ct).ConfigureAwait(false);
        try
        {
            return JsonSerializer.Deserialize<IpcEnvelope>(body, Json) ?? throw new InvalidDataException("Message IPC vide.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Message IPC illisible.", ex);
        }
    }
}

/// <summary>Enveloppe de tous les messages : un type et, selon le type, un état ou une alerte.</summary>
public sealed record IpcEnvelope(
    string Type,
    ServiceStatus? Status = null,
    ServiceAlert? Alert = null,
    string? Error = null,
    int? Version = null,
    StopChallenge? Challenge = null,
    StopRequest? Stop = null,
    StopResult? StopResult = null,
    AmsiScanRequest? Amsi = null,
    AmsiVerdict? AmsiVerdict = null);

/// <summary>Alerte émise par le service. Sévérité : "Info", "Warning" ou "Critical".</summary>
public sealed record ServiceAlert(string Severity, string Source, string Title, string Detail, DateTime TimestampUtc);

/// <summary>État d'un module hébergé par le service. State : "Active", "Disabled" ou "Unavailable".</summary>
public sealed record ModuleStatus(string Name, string State, string Text);

/// <summary>État global du service.</summary>
public sealed record ServiceStatus(
    int ProtocolVersion,
    int ProcessId,
    DateTime StartedUtc,
    string ActionProvider,
    bool KernelBacked,
    bool Elevated,
    IReadOnlyList<ModuleStatus> Modules)
{
    /// <summary>Vrai si un mot de passe de protection est configuré (arrêt authentifié possible).</summary>
    public bool StopPasswordConfigured { get; init; }

    public bool IsModuleActive(string name) =>
        Modules.Any(m => string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase) && m.State == "Active");
}

/// <summary>
/// Contenu soumis par le fournisseur AMSI (script PowerShell, VBScript, JScript, macro…).
/// <paramref name="Content"/> : octets bruts en Base64 (UTF-16LE pour PowerShell).
/// </summary>
public sealed record AmsiScanRequest(string App, string? ContentName, string Content);

/// <summary>Verdict renvoyé au fournisseur : <paramref name="Detected"/> = bloquer l'exécution.</summary>
public sealed record AmsiVerdict(bool Detected, int Score, string Reason);

/// <summary>Identité COM du fournisseur AMSI CoreGuard (doit correspondre à CoreGuard.AmsiProvider).</summary>
public static class AmsiProviderInfo
{
    public const string Clsid = "{6B3C2F1E-8A4D-4C7B-9E21-C0A5E9F4D317}";
    public const string ProvidersKey = @"SOFTWARE\Microsoft\AMSI\Providers\" + Clsid;
}

/// <summary>Noms des modules que le service peut héberger.</summary>
public static class ServiceModules
{
    public const string Behavior = "Behavior";
    public const string SelfDefense = "SelfDefense";
    public const string Canaries = "Canaries";
    public const string Amsi = "Amsi";
    public const string Memory = "Memory";
    public const string Credentials = "Credentials";
}
