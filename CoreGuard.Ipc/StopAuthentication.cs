using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace CoreGuard.Ipc;

/// <summary>
/// Arrêt légitime de la protection, par défi-réponse HMAC :
/// 1. le client demande un défi ; le service renvoie un nonce aléatoire à usage unique, le sel et le nombre d'itérations ;
/// 2. le client dérive la clé du mot de passe saisi (PBKDF2-SHA256) et renvoie HMAC-SHA256(clé, contexte || nonce) ;
/// 3. le service compare en temps constant avec la clé qu'il conserve.
/// Le mot de passe ne transite jamais sur le pipe, une réponse capturée ne peut pas être rejouée (nonce unique,
/// valable 60 s) et les essais sont limités (verrouillage de 5 min après 5 échecs).
/// </summary>
public static class StopProtocol
{
    public const int DefaultIterations = 600_000;
    public const int KeyBytes = 32;
    public const int NonceBytes = 32;
    private static readonly byte[] Context = "CoreGuard.Stop.v1"u8.ToArray();

    public static byte[] DeriveKey(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, KeyBytes);

    public static byte[] ComputeProof(byte[] key, byte[] nonce)
    {
        byte[] message = [.. Context, .. nonce];
        return HMACSHA256.HashData(key, message);
    }

    /// <summary>Calcule la réponse du client à partir du mot de passe (≈ 0,5 s : PBKDF2 volontairement coûteux).</summary>
    public static string Answer(string password, StopChallenge challenge)
    {
        byte[] key = DeriveKey(password, Convert.FromBase64String(challenge.Salt), challenge.Iterations);
        try { return Convert.ToBase64String(ComputeProof(key, Convert.FromBase64String(challenge.Nonce))); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}

/// <summary>Défi envoyé par le service.</summary>
public sealed record StopChallenge(string Nonce, string Salt, int Iterations);

/// <summary>Réponse du client à un défi.</summary>
public sealed record StopRequest(string Nonce, string Proof);

/// <summary>Résultat d'une demande d'arrêt.</summary>
public sealed record StopResult(bool Accepted, string Message);

/// <summary>Secret de protection stocké par le service (clé dérivée du mot de passe, jamais le mot de passe).</summary>
public sealed record ProtectionSecret(int Version, string Salt, int Iterations, string Key)
{
    public static ProtectionSecret Create(string password, int iterations = StopProtocol.DefaultIterations)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 8)
            throw new ArgumentException("Le mot de passe de protection doit contenir au moins 8 caractères.", nameof(password));

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] key = StopProtocol.DeriveKey(password, salt, iterations);
        return new ProtectionSecret(1, Convert.ToBase64String(salt), iterations, Convert.ToBase64String(key));
    }

    public static ProtectionSecret? Load(string path)
    {
        if (!File.Exists(path)) return null;
        var secret = JsonSerializer.Deserialize<ProtectionSecret>(File.ReadAllText(path), IpcContract.Json);
        return secret is { Version: 1, Iterations: > 0 } && !string.IsNullOrEmpty(secret.Key) ? secret : null;
    }

    /// <summary>
    /// Écrit le secret. <paramref name="restrictToAdmins"/> : ACL réservée à SYSTEM et aux Administrateurs
    /// (un programme utilisateur ne peut ni lire la clé, ni la remplacer par la sienne).
    /// </summary>
    public void Save(string path, bool restrictToAdmins)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        string temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(this, IpcContract.Json));
        if (restrictToAdmins)
        {
            var acl = new FileSecurity();
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(temp).SetAccessControl(acl);
        }
        File.Move(temp, path, overwrite: true);
    }
}

/// <summary>Côté service : émission des défis et vérification des réponses (thread-safe).</summary>
public sealed class StopAuthenticator
{
    public const int MaxFailures = 5;
    public static readonly TimeSpan NonceLifetime = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan Lockout = TimeSpan.FromMinutes(5);
    private const int MaxPendingNonces = 8;

    private readonly ProtectionSecret? _secret;
    private readonly TimeProvider _time;
    private readonly Dictionary<string, DateTimeOffset> _nonces = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private int _failures;
    private DateTimeOffset _lockedUntil = DateTimeOffset.MinValue;

    public StopAuthenticator(ProtectionSecret? secret, TimeProvider? time = null)
    {
        _secret = secret;
        _time = time ?? TimeProvider.System;
    }

    public bool IsConfigured => _secret is not null;

    /// <summary>Nouveau défi, ou null si aucun mot de passe n'est configuré.</summary>
    public StopChallenge? IssueChallenge()
    {
        if (_secret is null) return null;
        string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(StopProtocol.NonceBytes));
        lock (_gate)
        {
            PurgeExpired();
            if (_nonces.Count >= MaxPendingNonces)
                _nonces.Remove(_nonces.MinBy(n => n.Value).Key);
            _nonces[nonce] = _time.GetUtcNow() + NonceLifetime;
        }
        return new StopChallenge(nonce, _secret.Salt, _secret.Iterations);
    }

    public StopResult Verify(StopRequest? request)
    {
        if (_secret is null) return new StopResult(false, "Aucun mot de passe de protection n'est configuré sur ce poste.");
        if (request is null || string.IsNullOrEmpty(request.Nonce) || string.IsNullOrEmpty(request.Proof))
            return new StopResult(false, "Demande d'arrêt invalide.");

        lock (_gate)
        {
            DateTimeOffset now = _time.GetUtcNow();
            if (now < _lockedUntil)
                return new StopResult(false, $"Trop d'essais : réessayez dans {Math.Ceiling((_lockedUntil - now).TotalMinutes)} min.");

            // Nonce à usage unique : retiré dès la première présentation, qu'elle réussisse ou non
            if (!_nonces.Remove(request.Nonce, out DateTimeOffset expires) || now > expires)
                return new StopResult(false, "Défi expiré ou inconnu : recommencez.");

            byte[] expected;
            byte[] proof;
            try
            {
                expected = StopProtocol.ComputeProof(Convert.FromBase64String(_secret.Key), Convert.FromBase64String(request.Nonce));
                proof = Convert.FromBase64String(request.Proof);
            }
            catch (FormatException)
            {
                return RegisterFailure(now);
            }

            if (!CryptographicOperations.FixedTimeEquals(expected, proof))
                return RegisterFailure(now);

            _failures = 0;
            return new StopResult(true, "Arrêt autorisé.");
        }
    }

    private StopResult RegisterFailure(DateTimeOffset now)
    {
        if (++_failures >= MaxFailures)
        {
            _failures = 0;
            _lockedUntil = now + Lockout;
            return new StopResult(false, $"Mot de passe incorrect. Trop d'essais : verrouillage de {Lockout.TotalMinutes} min.");
        }
        return new StopResult(false, $"Mot de passe incorrect ({MaxFailures - _failures} essai(s) restant(s)).");
    }

    private void PurgeExpired()
    {
        DateTimeOffset now = _time.GetUtcNow();
        foreach (var expired in _nonces.Where(n => n.Value < now).Select(n => n.Key).ToList())
            _nonces.Remove(expired);
    }
}
