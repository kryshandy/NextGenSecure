namespace CoreGuard.Vault;

/// <summary>Configuration du coffre : emplacement du fichier et paramètres Argon2id.</summary>
public sealed record VaultOptions
{
    /// <summary>Chemin du fichier SQLite (défaut : vault.cgdb).</summary>
    public string FilePath { get; init; } = "vault.cgdb";

    /// <summary>Mémoire Argon2id en Kio (défaut 64 Mio).</summary>
    public int MemorySizeKb { get; init; } = 65536;

    /// <summary>Nombre d'itérations Argon2id.</summary>
    public int Iterations { get; init; } = 3;

    /// <summary>Degré de parallélisme Argon2id.</summary>
    public int DegreeOfParallelism { get; init; } = 4;
}
