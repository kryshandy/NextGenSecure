namespace CoreGuard.RealTime;

/// <summary>Zones de sécurité Windows (URLZONE) inscrites par le navigateur dans le flux Zone.Identifier.</summary>
public enum SecurityZone
{
    LocalMachine = 0,
    Intranet = 1,
    Trusted = 2,
    Internet = 3,
    Restricted = 4
}

/// <summary>« Marque du Web » d'un fichier téléchargé : zone d'origine, page de provenance et adresse du fichier.</summary>
public sealed record MarkOfTheWeb(SecurityZone Zone, string? ReferrerUrl, string? HostUrl)
{
    /// <summary>Vrai si le fichier vient d'Internet ou d'un site sur liste restreinte.</summary>
    public bool FromInternet => Zone is SecurityZone.Internet or SecurityZone.Restricted;

    /// <summary>Domaine d'où le fichier a été téléchargé (HostUrl, sinon la page de provenance).</summary>
    public string? SourceHost => HostOf(HostUrl) ?? HostOf(ReferrerUrl);

    /// <summary>
    /// Lit le flux NTFS secondaire « fichier:Zone.Identifier » (format INI écrit par Edge, Chrome, Firefox, Outlook…).
    /// Null si le fichier n'en a pas (copié depuis une clé USB, créé localement, système de fichiers non NTFS).
    /// </summary>
    public static MarkOfTheWeb? Read(string path)
    {
        try
        {
            string stream = path + ":Zone.Identifier";
            if (!File.Exists(path)) return null;
            using var reader = new StreamReader(new FileStream(stream, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
            char[] buffer = new char[8192]; // un flux Zone.Identifier fait quelques centaines d'octets
            int read = reader.ReadBlock(buffer, 0, buffer.Length);
            return Parse(new string(buffer, 0, read));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            return null; // pas de flux (FileNotFoundException est une IOException)
        }
    }

    /// <summary>Analyse le contenu INI du flux (donnée non fiable : seules trois clés sont lues).</summary>
    public static MarkOfTheWeb? Parse(string content)
    {
        int? zone = null;
        string? referrer = null, host = null;
        foreach (string raw in content.Split('\n'))
        {
            string line = raw.Trim();
            int eq = line.IndexOf('=');
            if (eq <= 0) continue;
            string key = line[..eq].Trim(), value = line[(eq + 1)..].Trim();
            if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase) && int.TryParse(value, out int z)) zone = z;
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase)) referrer = Clip(value);
            else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase)) host = Clip(value);
        }
        if (zone is null or < 0 or > 4) return null;
        return new MarkOfTheWeb((SecurityZone)zone.Value, referrer, host);
    }

    /// <summary>Écrit une marque du Web (démonstrations et tests).</summary>
    public static void Write(string path, SecurityZone zone, string? hostUrl, string? referrerUrl = null)
    {
        var lines = new List<string> { "[ZoneTransfer]", $"ZoneId={(int)zone}" };
        if (referrerUrl is not null) lines.Add("ReferrerUrl=" + referrerUrl);
        if (hostUrl is not null) lines.Add("HostUrl=" + hostUrl);
        File.WriteAllLines(path + ":Zone.Identifier", lines);
    }

    private static string? HostOf(string? url) =>
        url is not null && Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Host.Length > 0 ? u.Host.ToLowerInvariant() : null;

    private static string Clip(string value) => value.Length > 2048 ? value[..2048] : value;
}

/// <summary>Niveau affiché par le Smart Download Guard.</summary>
public enum DownloadLevel { Green, Orange, Red }

/// <summary>Évaluation d'un téléchargement : couleur et raisons lisibles.</summary>
public sealed record DownloadAssessment(DownloadLevel Level, IReadOnlyList<string> Reasons);

/// <summary>
/// Smart Download Guard (logique pure, testable) : combine le verdict des moteurs, la signature Authenticode, le type
/// de fichier et la marque du Web. Rouge = ne pas ouvrir ; orange = prudence ; vert = rien d'anormal.
/// </summary>
public static class DownloadRisk
{
    private static readonly HashSet<string> Executables = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".msi", ".scr", ".com", ".pif", ".dll", ".cpl", ".msix", ".appx", ".jar" };

    private static readonly HashSet<string> Scripts = new(StringComparer.OrdinalIgnoreCase)
        { ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".iso", ".img", ".vhd", ".vhdx" };

    private static readonly HashSet<string> MacroDocuments = new(StringComparer.OrdinalIgnoreCase)
        { ".docm", ".xlsm", ".pptm", ".xlam", ".dotm" };

    public static bool IsRunnable(string path) =>
        Executables.Contains(Path.GetExtension(path)) || Scripts.Contains(Path.GetExtension(path));

    /// <param name="verdict">« Sain », « Suspect » ou « Malveillant » (verdict des moteurs).</param>
    public static DownloadAssessment Assess(string path, MarkOfTheWeb? motw, bool signedAndValid, string? publisher, string verdict, int score)
    {
        var reasons = new List<string>();
        string ext = Path.GetExtension(path);
        bool executable = Executables.Contains(ext);
        bool script = Scripts.Contains(ext);
        bool macro = MacroDocuments.Contains(ext);

        if (motw is null) reasons.Add("origine inconnue (pas de marque du Web)");
        else if (motw.FromInternet) reasons.Add($"téléchargé depuis Internet{(motw.SourceHost is { } h ? $" ({h})" : "")}");
        else reasons.Add($"origine : zone {motw.Zone}");
        if (motw?.Zone == SecurityZone.Restricted) reasons.Add("le site d'origine est sur la liste des sites restreints");

        if (executable || script)
            reasons.Add(signedAndValid ? $"signé numériquement{(publisher is null ? "" : $" par {publisher}")}" : "non signé");
        if (script) reasons.Add("fichier exécutable sous forme de script, raccourci ou image disque");
        if (macro) reasons.Add("document avec macros");
        if (verdict != "Sain") reasons.Add($"verdict des moteurs : {verdict} (score {score}/100)");

        bool fromInternet = motw?.FromInternet ?? true; // sans marque, on reste prudent
        DownloadLevel level =
            verdict == "Malveillant" || motw?.Zone == SecurityZone.Restricted ? DownloadLevel.Red
            : verdict == "Suspect" && fromInternet && (executable || script) && !signedAndValid ? DownloadLevel.Red
            : verdict == "Suspect" ? DownloadLevel.Orange
            : fromInternet && ((executable || script) && !signedAndValid || macro) ? DownloadLevel.Orange
            : DownloadLevel.Green;
        return new DownloadAssessment(level, reasons);
    }
}
