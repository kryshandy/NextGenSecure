namespace CoreGuard.Extension;

/// <summary>Place d'un site dans la base de confiance.</summary>
public enum SiteTrust
{
    /// <summary>Domaine absent de toutes les listes.</summary>
    Unknown,
    /// <summary>Parmi les 100 000 domaines les plus visités (Tranco).</summary>
    Known,
    /// <summary>Hébergé chez un service où chacun publie (github.io, sites.google.com…) : réputation non transmise.</summary>
    ContentHost,
    /// <summary>Déclaré de confiance par l'utilisateur, confirmé dans CoreGuard.</summary>
    UserTrusted,
    /// <summary>Présent dans la liste noire (OpenPhish).</summary>
    Blocklisted
}

/// <summary>
/// Base de confiance locale (aucun accès réseau) : domaines connus, suffixes publics, liste noire, sites
/// de confiance de l'utilisateur. Chargée depuis <c>Data\</c> à côté de l'hôte et depuis le dossier utilisateur.
/// </summary>
public sealed class TrustBase
{
    /// <summary>Hôtes de services connus où n'importe qui peut publier une page (absents de la section privée de la PSL).</summary>
    private static readonly string[] SharedContentHosts =
    [
        "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "script.google.com", "storage.googleapis.com",
        "firebasestorage.googleapis.com", "forms.office.com", "onedrive.live.com", "1drv.ms", "sharepoint.com",
        "dl.dropboxusercontent.com", "ipfs.io", "cloudflare-ipfs.com", "translate.goog", "wixsite.com", "weebly.com",
        "000webhostapp.com", "glitch.me", "replit.dev", "repl.co", "notion.site", "canva.site", "framer.website",
        "webflow.io", "s3.amazonaws.com", "blob.core.windows.net", "web.core.windows.net", "ngrok.io", "ngrok-free.app",
        "trycloudflare.com", "workers.dev", "pages.dev", "netlify.app", "vercel.app", "github.io", "gitlab.io"
    ];

    private readonly HashSet<string> _known;
    private readonly HashSet<string> _blockedHosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _blockedUrls = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _trusted;

    public PublicSuffixList Suffixes { get; }
    public int KnownCount => _known.Count;
    public int BlockedCount => _blockedHosts.Count + _blockedUrls.Count;

    public TrustBase(PublicSuffixList suffixes, IEnumerable<string> knownDomains, IEnumerable<string> blockedUrls, IEnumerable<string> trustedDomains)
    {
        Suffixes = suffixes;
        _known = new HashSet<string>(Clean(knownDomains), StringComparer.OrdinalIgnoreCase);
        _trusted = new HashSet<string>(Clean(trustedDomains), StringComparer.OrdinalIgnoreCase);
        foreach (string url in Clean(blockedUrls)) AddBlocked(url);
    }

    /// <summary>Charge la base livrée (<paramref name="dataDir"/>) et les fichiers de l'utilisateur (confiance, mise à jour).</summary>
    public static TrustBase Load(string dataDir)
    {
        var psl = PublicSuffixList.Load(Path.Combine(dataDir, "public_suffix_list.dat"));
        IEnumerable<string> blocked = ReadLines(Path.Combine(dataDir, "phishing-blocklist.txt"))
            .Concat(ReadLines(CoreGuard.Ipc.PhishingFiles.BlocklistUpdate))
            .Concat(ReadLines(CoreGuard.Ipc.PhishingFiles.LocalBlocklist));
        return new TrustBase(psl, ReadLines(Path.Combine(dataDir, "top-domains.txt")), blocked,
            ReadLines(CoreGuard.Ipc.PhishingFiles.TrustedSites));
    }

    private static IEnumerable<string> ReadLines(string path) => File.Exists(path) ? File.ReadLines(path) : [];

    private static IEnumerable<string> Clean(IEnumerable<string> lines) =>
        lines.Select(l => l.Trim().TrimStart('﻿')).Where(l => l.Length > 0 && !l.StartsWith('#'));

    public string RegistrableDomain(string host) => Suffixes.GetRegistrableDomain(host);

    /// <summary>Classe un hôte. Ordre : confiance de l'utilisateur, liste noire, hébergeur partagé, domaine connu.</summary>
    public SiteTrust Classify(string url, string host)
    {
        string domain = RegistrableDomain(host);
        if (_trusted.Contains(domain) || _trusted.Contains(host)) return SiteTrust.UserTrusted;
        if (IsBlocklisted(url, host)) return SiteTrust.Blocklisted;
        if (IsContentHost(host)) return SiteTrust.ContentHost;
        return _known.Contains(domain) ? SiteTrust.Known : SiteTrust.Unknown;
    }

    public bool IsContentHost(string host)
    {
        if (Suffixes.GetSuffix(host).IsPrivate) return true;
        return SharedContentHosts.Any(h => host.Equals(h, StringComparison.OrdinalIgnoreCase)
                                          || host.EndsWith("." + h, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Liste noire : un hôte dédié (ni connu, ni partagé) est bloqué en entier ; sur un service connu ou partagé
    /// (docs.google.com, vercel.app…) seule l'adresse signalée est bloquée, pas tout le service.
    /// </summary>
    public bool IsBlocklisted(string url, string host)
    {
        if (_blockedHosts.Contains(host)) return true;
        string key = UrlKey(url);
        foreach (string blocked in _blockedUrls)
            if (key.StartsWith(blocked, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private void AddBlocked(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Host.Length == 0) return;
        string host = uri.Host.ToLowerInvariant();
        // Partagé = le domaine enregistrable est un service connu (docs.google.com → google.com). Un sous-domaine
        // d'hébergeur de la PSL (x.vercel.app) est, lui, un domaine enregistrable dédié : bloqué en entier.
        bool shared = _known.Contains(RegistrableDomain(host));
        string path = uri.PathAndQuery.TrimEnd('/');
        if (!shared) _blockedHosts.Add(host);
        else if (path.Length > 1) _blockedUrls.Add(UrlKey(url)); // jamais tout un service connu sur une entrée sans chemin
    }

    // Clé de comparaison : hôte + chemin, sans schéma ni fragment ni « / » final
    private static string UrlKey(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) ? (u.Host + u.PathAndQuery).TrimEnd('/').ToLowerInvariant() : url.ToLowerInvariant();
}
