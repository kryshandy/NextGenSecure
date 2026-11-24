using System.Buffers.Binary;
using System.Text.Json;

namespace CoreGuard.Extension;

/// <summary>
/// Protocole Native Messaging de Chrome : chaque message = 4 octets de longueur
/// (entier 32 bits, ordre natif little-endian) suivis du JSON UTF-8.
/// </summary>
public static class NativeMessagingProtocol
{
    /// <summary>Taille max acceptée depuis le navigateur (capture PNG en base64 incluse).</summary>
    public const int MaxIncomingBytes = 16 * 1024 * 1024;

    /// <summary>Limite imposée par Chrome aux messages hôte -> navigateur.</summary>
    public const int MaxOutgoingBytes = 1024 * 1024;

    /// <summary>Lit un message ; retourne null en fin de flux. Lève InvalidDataException si invalide.</summary>
    public static async Task<JsonDocument?> ReadAsync(Stream entree, CancellationToken ct = default)
    {
        var entete = new byte[4];
        if (!await ReadExactAsync(entree, entete, ct).ConfigureAwait(false)) return null;

        var longueur = BinaryPrimitives.ReadInt32LittleEndian(entete);
        // La longueur vient de l'extérieur : on la borne avant toute allocation.
        if (longueur < 0 || longueur > MaxIncomingBytes)
            throw new InvalidDataException($"Longueur de message invalide : {longueur}.");

        var corps = new byte[longueur];
        if (!await ReadExactAsync(entree, corps, ct).ConfigureAwait(false))
            throw new InvalidDataException("Flux interrompu au milieu d'un message.");

        try
        {
            return JsonDocument.Parse(corps);
        }
        catch (JsonException e)
        {
            throw new InvalidDataException("JSON invalide.", e);
        }
    }

    /// <summary>Écrit un message préfixé par sa longueur.</summary>
    public static async Task WriteAsync(Stream sortie, object message, CancellationToken ct = default)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions);
        if (json.Length > MaxOutgoingBytes)
            throw new InvalidOperationException("Réponse trop volumineuse pour Chrome (> 1 Mo).");

        var entete = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(entete, json.Length);
        await sortie.WriteAsync(entete, ct).ConfigureAwait(false);
        await sortie.WriteAsync(json, ct).ConfigureAwait(false);
        await sortie.FlushAsync(ct).ConfigureAwait(false);
    }

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    // Lit exactement buffer.Length octets ; false si fin de flux AVANT le premier octet.
    private static async Task<bool> ReadExactAsync(Stream flux, byte[] buffer, CancellationToken ct)
    {
        var lus = 0;
        while (lus < buffer.Length)
        {
            var n = await flux.ReadAsync(buffer.AsMemory(lus), ct).ConfigureAwait(false);
            if (n == 0)
            {
                if (lus == 0) return false;
                throw new InvalidDataException("Flux interrompu.");
            }
            lus += n;
        }
        return true;
    }
}
