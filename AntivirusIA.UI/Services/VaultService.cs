using System.Security.AccessControl;
using System.Security.Principal;
using AntivirusIA.Engines;
using CoreGuard.Ipc;
using CoreGuard.Vault;

namespace AntivirusIA.UI.Services;

/// <summary>
/// Gestionnaire de mots de passe : coffre CoreGuard (SQLite, clé Argon2id, AES-256-GCM) tenu par l'interface.
/// - fichier « vault.cgdb » dans %LocalAppData%\CoreGuard, ACL réservée à l'utilisateur et à SYSTEM ;
/// - verrouillage automatique après <see cref="AutoLock"/> d'inactivité (la clé est effacée de la mémoire) ;
/// - sert l'auto-remplissage de l'extension par <see cref="VaultBroker"/>, uniquement à l'hôte CoreGuard lancé
///   par un navigateur signé (Chrome, Edge, Brave), et uniquement pour l'hôte exact de la page.
/// </summary>
public sealed class VaultService : IDisposable
{
    public static readonly TimeSpan AutoLock = TimeSpan.FromMinutes(15);

    private static readonly Dictionary<string, string> Browsers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["chrome.exe"] = "Google", ["msedge.exe"] = "Microsoft", ["brave.exe"] = "Brave"
    };

    private readonly string _path;
    private readonly Vault _vault;
    private readonly AlertHub _alerts;
    private readonly AuthenticodeVerifier _authenticode = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Timer? _autoLock;

    public VaultService(string dataDir, AlertHub alerts)
    {
        _path = Path.Combine(dataDir, "vault.cgdb");
        _vault = new Vault(new VaultOptions { FilePath = _path });
        _alerts = alerts;
    }

    public bool Exists => File.Exists(_path);
    public bool IsUnlocked => _vault.IsUnlocked;

    /// <summary>Levé (thread quelconque) quand le coffre est créé, déverrouillé ou verrouillé.</summary>
    public event Action? StateChanged;

    /// <summary>Démarre le canal d'auto-remplissage pour l'extension (répond « verrouillé » tant que le coffre l'est).</summary>
    public void StartBroker() =>
        _ = Task.Run(() => VaultBroker.ServeAsync(LookupAsync, AuthorizeClient, _cts.Token, sites: SiteHandlers));

    /// <summary>Anti-phishing servi par le même canal (journal, revue par l'IA, confiance), même contrôle du client.</summary>
    public SiteHandlers? SiteHandlers { get; set; }

    public async Task CreateAsync(string masterPassword)
    {
        await _vault.CreateAsync(masterPassword);
        RestrictFileAcl(_path);
        await UnlockAsync(masterPassword);
    }

    public async Task<bool> UnlockAsync(string masterPassword)
    {
        bool ok = await _vault.UnlockAsync(masterPassword);
        if (ok) Touch();
        StateChanged?.Invoke();
        return ok;
    }

    public void Lock()
    {
        _vault.Lock();
        _autoLock?.Dispose();
        _autoLock = null;
        StateChanged?.Invoke();
    }

    public async Task<IReadOnlyList<CredentialEntry>> ListAsync() { Touch(); return await _vault.ListAsync(); }

    public async Task AddAsync(string title, string username, string url, string secret)
    {
        Touch();
        await _vault.AddAsync(title, username, url, secret);
    }

    public async Task DeleteAsync(Guid id) { Touch(); await _vault.DeleteAsync(id); }

    public static string GeneratePassword() => Vault.GeneratePassword(20, new PasswordOptions(ExcludeAmbiguous: true));

    // Toute activité repousse le verrouillage automatique
    private void Touch()
    {
        _autoLock?.Dispose();
        _autoLock = new Timer(_ =>
        {
            if (!_vault.IsUnlocked) return;
            _vault.Lock();
            StateChanged?.Invoke();
            _alerts.Publish(Models.AlertSeverity.Info, "Coffre-fort", "Coffre verrouillé automatiquement", $"Après {AutoLock.TotalMinutes} min d'inactivité.");
        }, null, AutoLock, Timeout.InfiniteTimeSpan);
    }

    /// <summary>Identifiant pour l'URL d'une page : hôte identique, ou sous-domaine de l'hôte enregistré.</summary>
    private async Task<CredentialLookup> LookupAsync(string url)
    {
        if (!_vault.IsUnlocked) return CredentialLookup.VaultLocked;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var page)) return CredentialLookup.NotFound;

        await _gate.WaitAsync();
        try
        {
            var entries = await _vault.ListAsync();
            var match = entries
                .Where(e => VaultBroker.MatchesHost(e.Url, page.Host))
                .OrderByDescending(e => e.UpdatedUtc)
                .FirstOrDefault();
            if (match is null) return CredentialLookup.NotFound;

            string? secret = await _vault.GetSecretAsync(match.Id);
            Touch();
            _alerts.Publish(Models.AlertSeverity.Info, "Coffre-fort", "Identifiant rempli par l'extension", $"{match.Title} sur {page.Host}");
            return secret is null ? CredentialLookup.NotFound : new CredentialLookup(true, match.Username, secret, false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Seul l'hôte CoreGuard lancé par un navigateur signé peut obtenir un mot de passe. Un programme malveillant
    /// qui lancerait lui-même l'hôte (ou se connecterait au pipe) n'a pas de navigateur signé dans son ascendance.
    /// </summary>
    private bool AuthorizeClient(int pid)
    {
        string? client = ProcessAncestry.ImagePath(pid);
        if (client is null || !Path.GetFileName(client).Equals("CoreGuard.Extension.exe", StringComparison.OrdinalIgnoreCase))
            return Deny(pid, client, "client inattendu");

        foreach (int ancestor in ProcessAncestry.Ancestors(pid))
        {
            string? image = ProcessAncestry.ImagePath(ancestor);
            if (image is null || !Browsers.TryGetValue(Path.GetFileName(image), out string? publisher)) continue;
            var trust = _authenticode.EvaluateAsync(image).GetAwaiter().GetResult();
            if (trust.IsTrusted && trust.Publisher?.Contains(publisher, StringComparison.OrdinalIgnoreCase) == true) return true;
        }
        return Deny(pid, client, "non lancé par un navigateur signé");
    }

    private bool Deny(int pid, string? image, string reason)
    {
        _alerts.Publish(Models.AlertSeverity.Critical, "Coffre-fort", "Demande de mot de passe refusée",
            $"{Path.GetFileName(image ?? "?")} (PID {pid}) : {reason}. Tentative possible de vol du coffre.");
        return false;
    }

    private static void RestrictFileAcl(string path)
    {
        try
        {
            var acl = new FileSecurity();
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(acl);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            // Le coffre reste chiffré ; l'ACL n'est qu'une protection supplémentaire
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _autoLock?.Dispose();
        _vault.Dispose();
    }
}
