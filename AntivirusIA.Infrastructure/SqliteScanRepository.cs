using System.Globalization;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;
using Microsoft.Data.Sqlite;

namespace AntivirusIA.Infrastructure;

public sealed class SqliteScanRepository : IScanRepository
{
    private readonly string _connectionString;

    public SqliteScanRepository(string cheminBase)
    {
        string? dossier = Path.GetDirectoryName(cheminBase);
        if (!string.IsNullOrEmpty(dossier))
            Directory.CreateDirectory(dossier);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = cheminBase,
            Pooling = false
        }.ToString();

        using var connexion = new SqliteConnection(_connectionString);
        connexion.Open();
        using var commande = connexion.CreateCommand();
        commande.CommandText = """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date_utc TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT,
                score INTEGER NOT NULL,
                verdict INTEGER NOT NULL,
                details TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256);
            CREATE TABLE IF NOT EXISTS whitelist (
                sha256 TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                date_utc TEXT NOT NULL
            );
            """;
        commande.ExecuteNonQuery();
    }

    public async Task SaveScanAsync(ScanResult result, CancellationToken ct = default)
    {
        await using var connexion = await OuvrirAsync(ct);
        await using var commande = connexion.CreateCommand();
        commande.CommandText = """
            INSERT INTO scans (date_utc, path, sha256, score, verdict, details)
            VALUES ($date, $path, $sha, $score, $verdict, $details);
            """;
        commande.Parameters.AddWithValue("$date", DateTime.UtcNow.ToString("O"));
        commande.Parameters.AddWithValue("$path", result.File.FullPath);
        commande.Parameters.AddWithValue("$sha", (object?)result.File.Sha256 ?? DBNull.Value);
        commande.Parameters.AddWithValue("$score", result.Score);
        commande.Parameters.AddWithValue("$verdict", (int)result.Verdict);
        commande.Parameters.AddWithValue("$details", string.Join(" | ",
            result.Indicators.Select(i => $"[{i.Source}] {i.Description} (+{i.Points})")));
        await commande.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<ScanRecord>> GetHistoryAsync(int limite = 100, CancellationToken ct = default)
    {
        await using var connexion = await OuvrirAsync(ct);
        await using var commande = connexion.CreateCommand();
        commande.CommandText = """
            SELECT id, date_utc, path, sha256, score, verdict, details
            FROM scans ORDER BY id DESC LIMIT $limite;
            """;
        commande.Parameters.AddWithValue("$limite", limite);

        var resultats = new List<ScanRecord>();
        await using var lecteur = await commande.ExecuteReaderAsync(ct);
        while (await lecteur.ReadAsync(ct))
            resultats.Add(LireRecord(lecteur));
        return resultats;
    }

    public async Task<ScanRecord?> GetLastScanByHashAsync(string sha256, CancellationToken ct = default)
    {
        await using var connexion = await OuvrirAsync(ct);
        await using var commande = connexion.CreateCommand();
        commande.CommandText = """
            SELECT id, date_utc, path, sha256, score, verdict, details
            FROM scans WHERE sha256 = $sha ORDER BY id DESC LIMIT 1;
            """;
        commande.Parameters.AddWithValue("$sha", sha256.ToLowerInvariant());

        await using var lecteur = await commande.ExecuteReaderAsync(ct);
        return await lecteur.ReadAsync(ct) ? LireRecord(lecteur) : null;
    }

    public async Task AddToWhitelistAsync(string sha256, string cheminOrigine, CancellationToken ct = default)
    {
        await using var connexion = await OuvrirAsync(ct);
        await using var commande = connexion.CreateCommand();
        commande.CommandText = """
            INSERT OR REPLACE INTO whitelist (sha256, original_path, date_utc)
            VALUES ($sha, $path, $date);
            """;
        commande.Parameters.AddWithValue("$sha", sha256.ToLowerInvariant());
        commande.Parameters.AddWithValue("$path", cheminOrigine);
        commande.Parameters.AddWithValue("$date", DateTime.UtcNow.ToString("O"));
        await commande.ExecuteNonQueryAsync(ct);
    }

    public async Task RemoveFromWhitelistAsync(string sha256, CancellationToken ct = default)
    {
        await using var connexion = await OuvrirAsync(ct);
        await using var commande = connexion.CreateCommand();
        commande.CommandText = "DELETE FROM whitelist WHERE sha256 = $sha;";
        commande.Parameters.AddWithValue("$sha", sha256.ToLowerInvariant());
        await commande.ExecuteNonQueryAsync(ct);
    }

    public async Task<bool> IsWhitelistedAsync(string sha256, CancellationToken ct = default)
    {
        await using var connexion = await OuvrirAsync(ct);
        await using var commande = connexion.CreateCommand();
        commande.CommandText = "SELECT 1 FROM whitelist WHERE sha256 = $sha LIMIT 1;";
        commande.Parameters.AddWithValue("$sha", sha256.ToLowerInvariant());
        return await commande.ExecuteScalarAsync(ct) is not null;
    }

    // ---------- Méthodes internes ----------

    private async Task<SqliteConnection> OuvrirAsync(CancellationToken ct)
    {
        var connexion = new SqliteConnection(_connectionString);
        await connexion.OpenAsync(ct);
        return connexion;
    }

    private static ScanRecord LireRecord(SqliteDataReader lecteur) => new(
        lecteur.GetInt64(0),
        DateTime.Parse(lecteur.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
        lecteur.GetString(2),
        lecteur.IsDBNull(3) ? null : lecteur.GetString(3),
        lecteur.GetInt32(4),
        (Verdict)lecteur.GetInt32(5),
        lecteur.GetString(6));
}