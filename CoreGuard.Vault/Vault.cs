using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace CoreGuard.Vault;

/// <summary>
/// Coffre-fort local : SQLite + Argon2id (dérivation de clé) + AES-256-GCM (chiffrement des secrets).
/// Aucun secret n'est journalisé ni inclus dans les messages d'exception.
/// </summary>
public sealed class Vault : IVault
{
    private const int KeySize = 32;
    private const int SaltSize = 16;
    private const int NonceSize = 12; // taille standard AES-GCM
    private const int TagSize = 16;
    private static readonly byte[] VerifierPlain = "CoreGuard.Vault.v1"u8.ToArray();
    private static readonly byte[] VerifierAad = "verifier"u8.ToArray();

    private readonly VaultOptions _options;
    private readonly string _connectionString;
    private byte[]? _key;

    public Vault() : this(new VaultOptions()) { }

    public Vault(VaultOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.FilePath);
        _options = options;
        // Pooling désactivé : le fichier est libéré dès la fermeture de la connexion.
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = options.FilePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false
        }.ToString();
    }

    public bool IsUnlocked => _key is not null;

    // ---------------------------------------------------------------- Création / déverrouillage

    public async Task CreateAsync(string masterPassword, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(masterPassword);

        await using var conn = await OpenAsync(ct);
        await ExecAsync(conn, """
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                url TEXT NOT NULL,
                updated_utc TEXT NOT NULL,
                nonce BLOB NOT NULL,
                tag BLOB NOT NULL,
                ciphertext BLOB NOT NULL);
            """, ct);

        if (await GetMetaAsync(conn, "salt", ct) is not null)
            throw new InvalidOperationException("Un coffre existe déjà à cet emplacement.");

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = DeriveKey(masterPassword, salt, _options.MemorySizeKb, _options.Iterations, _options.DegreeOfParallelism);
        try
        {
            var (nonce, tag, cipher) = Encrypt(key, VerifierPlain, VerifierAad);
            await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);
            await SetMetaAsync(conn, tx, "salt", salt, ct);
            await SetMetaAsync(conn, tx, "mem", Int(_options.MemorySizeKb), ct);
            await SetMetaAsync(conn, tx, "iter", Int(_options.Iterations), ct);
            await SetMetaAsync(conn, tx, "par", Int(_options.DegreeOfParallelism), ct);
            await SetMetaAsync(conn, tx, "v_nonce", nonce, ct);
            await SetMetaAsync(conn, tx, "v_tag", tag, ct);
            await SetMetaAsync(conn, tx, "v_cipher", cipher, ct);
            await tx.CommitAsync(ct);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public async Task<bool> UnlockAsync(string masterPassword, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(masterPassword) || !File.Exists(_options.FilePath))
            return false;

        byte[]? key = null;
        try
        {
            await using var conn = await OpenAsync(ct);
            var salt = await GetMetaAsync(conn, "salt", ct);
            var nonce = await GetMetaAsync(conn, "v_nonce", ct);
            var tag = await GetMetaAsync(conn, "v_tag", ct);
            var cipher = await GetMetaAsync(conn, "v_cipher", ct);
            var mem = await GetMetaAsync(conn, "mem", ct);
            var iter = await GetMetaAsync(conn, "iter", ct);
            var par = await GetMetaAsync(conn, "par", ct);
            if (salt is null || nonce is null || tag is null || cipher is null || mem is null || iter is null || par is null)
                return false;

            // Les paramètres Argon2 sont lus depuis le coffre (rétrocompatibilité en cas d'évolution).
            key = DeriveKey(masterPassword, salt, ToInt(mem), ToInt(iter), ToInt(par));
            var plain = new byte[cipher.Length];
            try
            {
                using var gcm = new AesGcm(key, TagSize);
                gcm.Decrypt(nonce, cipher, tag, plain, VerifierAad);
                if (!CryptographicOperations.FixedTimeEquals(plain, VerifierPlain))
                    return false;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }

            var old = _key;
            _key = key;
            key = null; // propriété transférée
            if (old is not null) CryptographicOperations.ZeroMemory(old);
            return true;
        }
        catch (CryptographicException) { return false; } // mauvais mot de passe / données altérées
        catch (SqliteException) { return false; }        // fichier invalide
        catch (ArgumentException) { return false; }      // paramètres corrompus
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }

    public void Lock()
    {
        var key = Interlocked.Exchange(ref _key, null);
        if (key is not null) CryptographicOperations.ZeroMemory(key);
    }

    public void Dispose() => Lock();

    // ---------------------------------------------------------------- CRUD

    public async Task<IReadOnlyList<CredentialEntry>> ListAsync(CancellationToken ct = default)
    {
        RequireKey();
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, title, username, url, updated_utc FROM entries ORDER BY title COLLATE NOCASE";
        var list = new List<CredentialEntry>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(ReadEntry(r));
        return list;
    }

    public async Task<CredentialEntry?> GetAsync(Guid id, CancellationToken ct = default)
    {
        RequireKey();
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, title, username, url, updated_utc FROM entries WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id.ToString());
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? ReadEntry(r) : null;
    }

    public async Task<CredentialEntry> AddAsync(string title, string username, string url, string secret, CancellationToken ct = default)
    {
        var key = RequireKey();
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentNullException.ThrowIfNull(secret);

        var entry = new CredentialEntry(Guid.NewGuid(), title, username ?? "", url ?? "", DateTime.UtcNow);
        var (nonce, tag, cipher) = Encrypt(key, Encoding.UTF8.GetBytes(secret), Aad(entry.Id));

        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO entries (id, title, username, url, updated_utc, nonce, tag, ciphertext)
            VALUES ($id, $title, $user, $url, $upd, $nonce, $tag, $cipher)
            """;
        cmd.Parameters.AddWithValue("$id", entry.Id.ToString());
        cmd.Parameters.AddWithValue("$title", entry.Title);
        cmd.Parameters.AddWithValue("$user", entry.Username);
        cmd.Parameters.AddWithValue("$url", entry.Url);
        cmd.Parameters.AddWithValue("$upd", entry.UpdatedUtc.ToString("O", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$nonce", nonce);
        cmd.Parameters.AddWithValue("$tag", tag);
        cmd.Parameters.AddWithValue("$cipher", cipher);
        await cmd.ExecuteNonQueryAsync(ct);
        return entry;
    }

    public async Task<bool> UpdateAsync(Guid id, string title, string username, string url, string? secret, CancellationToken ct = default)
    {
        var key = RequireKey();
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        var now = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        if (secret is null)
        {
            cmd.CommandText = "UPDATE entries SET title=$title, username=$user, url=$url, updated_utc=$upd WHERE id=$id";
        }
        else
        {
            // Nouveau nonce à chaque réécriture du secret (jamais de réutilisation).
            var (nonce, tag, cipher) = Encrypt(key, Encoding.UTF8.GetBytes(secret), Aad(id));
            cmd.CommandText = "UPDATE entries SET title=$title, username=$user, url=$url, updated_utc=$upd, nonce=$nonce, tag=$tag, ciphertext=$cipher WHERE id=$id";
            cmd.Parameters.AddWithValue("$nonce", nonce);
            cmd.Parameters.AddWithValue("$tag", tag);
            cmd.Parameters.AddWithValue("$cipher", cipher);
        }
        cmd.Parameters.AddWithValue("$id", id.ToString());
        cmd.Parameters.AddWithValue("$title", title);
        cmd.Parameters.AddWithValue("$user", username ?? "");
        cmd.Parameters.AddWithValue("$url", url ?? "");
        cmd.Parameters.AddWithValue("$upd", now);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        RequireKey();
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM entries WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id.ToString());
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    public async Task<string?> GetSecretAsync(Guid id, CancellationToken ct = default)
    {
        var key = RequireKey();
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT nonce, tag, ciphertext FROM entries WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id.ToString());
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return null;

        var nonce = (byte[])r["nonce"];
        var tag = (byte[])r["tag"];
        var cipher = (byte[])r["ciphertext"];
        var plain = new byte[cipher.Length];
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            gcm.Decrypt(nonce, cipher, tag, plain, Aad(id)); // vérifie le tag d'authentification
            return Encoding.UTF8.GetString(plain);
        }
        catch (CryptographicException)
        {
            // Message volontairement neutre : aucun détail sur le contenu.
            throw new InvalidDataException("Entrée corrompue ou altérée : authentification échouée.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    // ---------------------------------------------------------------- Générateur de mots de passe

    private const string Lower = "abcdefghijklmnopqrstuvwxyz";
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Digit = "0123456789";
    private const string Symbol = "!@#$%^&*()-_=+[]{};:,.<>?/~";
    private const string Ambiguous = "0O1lI|`'\"";

    /// <summary>
    /// Génère un mot de passe aléatoire avec le RNG cryptographique (sélection sans biais).
    /// Garantit au moins un caractère de chaque catégorie activée.
    /// </summary>
    public static string GeneratePassword(int length, PasswordOptions? options = null)
    {
        options ??= new PasswordOptions();
        var sets = new List<string>();
        if (options.Lowercase) sets.Add(Lower);
        if (options.Uppercase) sets.Add(Upper);
        if (options.Digits) sets.Add(Digit);
        if (options.Symbols) sets.Add(Symbol);
        if (options.ExcludeAmbiguous)
            sets = sets.Select(s => new string(s.Where(c => !Ambiguous.Contains(c)).ToArray())).ToList();

        if (sets.Count == 0)
            throw new ArgumentException("Au moins une catégorie de caractères doit être activée.", nameof(options));
        if (length < sets.Count || length > 4096)
            throw new ArgumentOutOfRangeException(nameof(length), $"La longueur doit être comprise entre {sets.Count} et 4096.");

        var all = string.Concat(sets);
        var chars = new char[length];
        for (var i = 0; i < sets.Count; i++)
            chars[i] = sets[i][RandomNumberGenerator.GetInt32(sets[i].Length)];
        for (var i = sets.Count; i < length; i++)
            chars[i] = all[RandomNumberGenerator.GetInt32(all.Length)];

        RandomNumberGenerator.Shuffle(chars.AsSpan()); // mélange cryptographique des positions
        return new string(chars);
    }

    // ---------------------------------------------------------------- Helpers internes

    private byte[] RequireKey() =>
        _key ?? throw new InvalidOperationException("Le coffre est verrouillé.");

    private static byte[] Aad(Guid id) => id.ToByteArray(); // lie le chiffré à son entrée

    private static byte[] DeriveKey(string password, byte[] salt, int memoryKb, int iterations, int parallelism)
    {
        var pwd = Encoding.UTF8.GetBytes(password);
        try
        {
            using var argon = new Argon2id(pwd)
            {
                Salt = salt,
                MemorySize = memoryKb,
                Iterations = iterations,
                DegreeOfParallelism = parallelism
            };
            return argon.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwd);
        }
    }

    private static (byte[] Nonce, byte[] Tag, byte[] Cipher) Encrypt(byte[] key, byte[] plain, byte[] aad)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize); // 96 bits aléatoires, unique par chiffrement
        var tag = new byte[TagSize];
        var cipher = new byte[plain.Length];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plain, cipher, tag, aad);
        return (nonce, tag, cipher);
    }

    private static CredentialEntry ReadEntry(SqliteDataReader r) => new(
        Guid.Parse(r.GetString(0)), r.GetString(1), r.GetString(2), r.GetString(3),
        DateTime.Parse(r.GetString(4), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind));

    private static byte[] Int(int v) => BitConverter.GetBytes(v);
    private static int ToInt(byte[] b) => BitConverter.ToInt32(b, 0);

    private async Task<SqliteConnection> OpenAsync(CancellationToken ct)
    {
        var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct);
        return conn;
    }

    private static async Task ExecAsync(SqliteConnection conn, string sql, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task<byte[]?> GetMetaAsync(SqliteConnection conn, string key, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM meta WHERE key = $k";
        cmd.Parameters.AddWithValue("$k", key);
        return await cmd.ExecuteScalarAsync(ct) as byte[];
    }

    private static async Task SetMetaAsync(SqliteConnection conn, SqliteTransaction tx, string key, byte[] value, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT OR REPLACE INTO meta (key, value) VALUES ($k, $v)";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
