namespace CoreGuard.Extension;

/// <summary>
/// Public Suffix List (publicsuffix.org) : donne le vrai « domaine enregistrable » d'un hôte
/// (<c>www.impots.gouv.fr</c> → <c>impots.gouv.fr</c>, <c>x.vercel.app</c> → <c>x.vercel.app</c>).
/// Les suffixes de la section PRIVÉE sont des services où n'importe qui publie (github.io, vercel.app,
/// blogspot.com…) : un site qui y est hébergé ne profite jamais de la réputation du service.
/// </summary>
public sealed class PublicSuffixList
{
    private readonly HashSet<string> _rules = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _wildcards = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _exceptions = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _private = new(StringComparer.OrdinalIgnoreCase);

    public int Count => _rules.Count + _wildcards.Count + _exceptions.Count;

    public static PublicSuffixList Parse(IEnumerable<string> lines)
    {
        var list = new PublicSuffixList();
        bool inPrivate = false;
        foreach (string raw in lines)
        {
            string line = raw.Trim();
            if (line.Contains("===BEGIN PRIVATE DOMAINS===", StringComparison.Ordinal)) { inPrivate = true; continue; }
            if (line.Contains("===END PRIVATE DOMAINS===", StringComparison.Ordinal)) { inPrivate = false; continue; }
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal)) continue;
            int space = line.IndexOfAny([' ', '\t']);
            if (space > 0) line = line[..space];
            line = line.ToLowerInvariant();

            string bare;
            if (line.StartsWith('!')) { bare = line[1..]; list._exceptions.Add(bare); }
            else if (line.StartsWith("*.", StringComparison.Ordinal)) { bare = line[2..]; list._wildcards.Add(bare); }
            else { bare = line; list._rules.Add(bare); }
            if (inPrivate) list._private.Add(bare);
        }
        return list;
    }

    public static PublicSuffixList Load(string path) => Parse(File.ReadLines(path));

    /// <summary>Suffixe public le plus long de l'hôte, et s'il appartient à la section privée (hébergeur).</summary>
    public (string Suffix, bool IsPrivate) GetSuffix(string host)
    {
        var labels = host.Trim('.').ToLowerInvariant().Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < labels.Length; i++)
        {
            string candidate = string.Join('.', labels[i..]);
            if (_exceptions.Contains(candidate))
            {
                string suffix = string.Join('.', labels[(i + 1)..]);
                return (suffix, _private.Contains(candidate));
            }
            if (_rules.Contains(candidate)) return (candidate, _private.Contains(candidate));
            if (i + 1 < labels.Length)
            {
                string parent = string.Join('.', labels[(i + 1)..]);
                if (_wildcards.Contains(parent)) return (candidate, _private.Contains(parent));
            }
        }
        return (labels.Length > 0 ? labels[^1] : host, false); // règle par défaut « * »
    }

    /// <summary>Domaine enregistrable (suffixe public + un label) ; l'hôte lui-même s'il est un suffixe.</summary>
    public string GetRegistrableDomain(string host)
    {
        var (suffix, _) = GetSuffix(host);
        string h = host.Trim('.').ToLowerInvariant();
        if (h.Length <= suffix.Length) return h;
        string before = h[..^(suffix.Length + 1)];
        int dot = before.LastIndexOf('.');
        return (dot < 0 ? before : before[(dot + 1)..]) + "." + suffix;
    }
}
