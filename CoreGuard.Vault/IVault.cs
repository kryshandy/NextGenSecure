namespace CoreGuard.Vault;

/// <summary>Entrée du coffre-fort exposée sans secret (le mot de passe n'est jamais inclus).</summary>
public sealed record CredentialEntry(Guid Id, string Title, string Username, string Url, DateTime UpdatedUtc);

/// <summary>Options de génération de mot de passe.</summary>
/// <param name="Lowercase">Inclure des minuscules.</param>
/// <param name="Uppercase">Inclure des majuscules.</param>
/// <param name="Digits">Inclure des chiffres.</param>
/// <param name="Symbols">Inclure des symboles.</param>
/// <param name="ExcludeAmbiguous">Exclure les caractères ambigus (0/O, 1/l/I...).</param>
public sealed record PasswordOptions(
    bool Lowercase = true,
    bool Uppercase = true,
    bool Digits = true,
    bool Symbols = true,
    bool ExcludeAmbiguous = false);

/// <summary>Contrat du coffre-fort de mots de passe local chiffré.</summary>
public interface IVault : IDisposable
{
    /// <summary>Indique si le coffre est actuellement déverrouillé.</summary>
    bool IsUnlocked { get; }

    /// <summary>Crée un nouveau coffre protégé par le mot de passe maître (échoue s'il existe déjà).</summary>
    Task CreateAsync(string masterPassword, CancellationToken ct = default);

    /// <summary>Déverrouille le coffre. Retourne false si le mot de passe est incorrect ou le coffre absent/corrompu.</summary>
    Task<bool> UnlockAsync(string masterPassword, CancellationToken ct = default);

    /// <summary>Verrouille le coffre et efface la clé de la mémoire.</summary>
    void Lock();

    /// <summary>Liste les entrées (sans secrets).</summary>
    Task<IReadOnlyList<CredentialEntry>> ListAsync(CancellationToken ct = default);

    /// <summary>Récupère une entrée (sans secret), ou null si inconnue.</summary>
    Task<CredentialEntry?> GetAsync(Guid id, CancellationToken ct = default);

    /// <summary>Ajoute une entrée chiffrée et retourne ses métadonnées.</summary>
    Task<CredentialEntry> AddAsync(string title, string username, string url, string secret, CancellationToken ct = default);

    /// <summary>Met à jour une entrée. Si <paramref name="secret"/> est null, le secret existant est conservé. Retourne false si inconnue.</summary>
    Task<bool> UpdateAsync(Guid id, string title, string username, string url, string? secret, CancellationToken ct = default);

    /// <summary>Supprime une entrée. Retourne false si inconnue.</summary>
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);

    /// <summary>Déchiffre et retourne le secret d'une entrée (seule voie d'accès au clair). Null si inconnue.</summary>
    Task<string?> GetSecretAsync(Guid id, CancellationToken ct = default);
}
