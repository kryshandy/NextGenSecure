using System.Text;
using System.Text.RegularExpressions;

namespace CoreGuard.Behavior;

/// <summary>
/// Moteur de règles comportementales pur : aucune dépendance à une API Windows.
/// Thread-safe. Toutes les entrées (image, ligne de commande) sont non fiables et assainies.
/// </summary>
public sealed partial class BehaviorRuleEngine
{
    public const string RuleOfficeSpawn = "OFFICE_SPAWNS_SHELL";
    public const string RuleShadowDelete = "SHADOW_COPY_DELETE";
    public const string RulePersistence = "PERSISTENCE_COMMAND";

    public const int SeverityPersistence = 60;
    public const int SeverityOfficeSpawn = 70;
    public const int SeverityOfficeSpawnEncoded = 90;
    public const int SeverityMax = 100;

    private const int MaxCommandLength = 8192;
    private const int MaxDetailLength = 512;
    private const int MaxTrackedProcesses = 4096;

    private static readonly HashSet<string> OfficeImages = new(StringComparer.OrdinalIgnoreCase)
        { "winword", "excel", "outlook", "powerpnt", "onenote", "msaccess", "mspub" };

    private static readonly HashSet<string> ShellImages = new(StringComparer.OrdinalIgnoreCase)
        { "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta" };

    // Mémorise pid -> image pour retrouver le parent (ETW ne fournit que le ParentPid).
    private readonly Dictionary<int, string> _images = new();
    private readonly Queue<int> _order = new();
    private readonly object _lock = new();

    /// <summary>Évalue un événement et renvoie les alertes (liste vide si rien de suspect).</summary>
    public IReadOnlyList<BehaviorAlert> Evaluate(ProcessEvent? evt)
    {
        if (evt is null) return [];

        string image = NormalizeImage(evt.Image);
        string cmd = Sanitize(evt.CommandLine, MaxCommandLength);
        string? parentImage;

        lock (_lock)
        {
            _images.TryGetValue(evt.ParentPid, out parentImage);
            Track(evt.Pid, image);
        }

        var alerts = new List<BehaviorAlert>();

        if (parentImage is not null && OfficeImages.Contains(parentImage) && ShellImages.Contains(image))
        {
            bool encoded = EncodedArgRegex().IsMatch(cmd) || LongBase64Regex().IsMatch(cmd);
            alerts.Add(new BehaviorAlert(RuleOfficeSpawn,
                Truncate($"{parentImage} a lancé {image}{(encoded ? " avec argument encodé Base64" : "")} : {cmd}"),
                encoded ? SeverityOfficeSpawnEncoded : SeverityOfficeSpawn, evt.Pid));
        }

        string lower = cmd.ToLowerInvariant();

        if (IsShadowDelete(image, lower))
            alerts.Add(new BehaviorAlert(RuleShadowDelete,
                Truncate($"Suppression des clichés instantanés par {image} : {cmd}"), SeverityMax, evt.Pid));

        string? persistence = DetectPersistence(image, lower);
        if (persistence is not null)
            alerts.Add(new BehaviorAlert(RulePersistence,
                Truncate($"{persistence} par {image} : {cmd}"), SeverityPersistence, evt.Pid));

        return alerts;
    }

    private static bool IsShadowDelete(string image, string lower) => image switch
    {
        "vssadmin" => VssDeleteRegex().IsMatch(lower),
        "wmic" => lower.Contains("shadowcopy") && DeleteWordRegex().IsMatch(lower),
        "diskshadow" => DeleteWordRegex().IsMatch(lower),
        // Variante via PowerShell/WMI : Get-WmiObject Win32_ShadowCopy | Delete
        "powershell" or "pwsh" => lower.Contains("win32_shadowcopy") && (lower.Contains("delete") || lower.Contains("remove-")),
        _ => false,
    };

    private static string? DetectPersistence(string image, string lower) => image switch
    {
        "schtasks" when CreateSwitchRegex().IsMatch(lower) => "Création de tâche planifiée",
        "sc" when ScCreateRegex().IsMatch(lower) => "Création de service",
        "reg" when RegAddRunRegex().IsMatch(lower) => "Ajout d'une clé de démarrage automatique (Run)",
        _ => null,
    };

    private void Track(int pid, string image)
    {
        if (!_images.ContainsKey(pid)) _order.Enqueue(pid);
        _images[pid] = image;
        while (_order.Count > MaxTrackedProcesses)
            _images.Remove(_order.Dequeue());
    }

    /// <summary>Extrait le nom de fichier sans extension, en minuscules, depuis un chemin non fiable.</summary>
    internal static string NormalizeImage(string? image)
    {
        string s = Sanitize(image, 520).Trim().Trim('"');
        int slash = Math.Max(s.LastIndexOf('\\'), s.LastIndexOf('/'));
        if (slash >= 0) s = s[(slash + 1)..];
        if (s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) s = s[..^4];
        return s.ToLowerInvariant();
    }

    /// <summary>Supprime les caractères de contrôle (log injection) et borne la longueur.</summary>
    internal static string Sanitize(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var sb = new StringBuilder(Math.Min(value.Length, max));
        foreach (char c in value)
        {
            if (sb.Length >= max) break;
            sb.Append(char.IsControl(c) ? ' ' : c);
        }
        return sb.ToString();
    }

    private static string Truncate(string s) => s.Length <= MaxDetailLength ? s : s[..MaxDetailLength];

    [GeneratedRegex(@"\bdelete\s+shadows\b")]
    private static partial Regex VssDeleteRegex();

    [GeneratedRegex(@"\bdelete\b")]
    private static partial Regex DeleteWordRegex();

    [GeneratedRegex(@"[/-]create\b")]
    private static partial Regex CreateSwitchRegex();

    [GeneratedRegex(@"(^|\s)create(\s|$)")]
    private static partial Regex ScCreateRegex();

    [GeneratedRegex(@"\badd\b.*\\currentversion\\run(once)?(\\|\s|$|"")")]
    private static partial Regex RegAddRunRegex();

    // -e / -ec / -enc / -EncodedCommand suivi d'un blob Base64
    [GeneratedRegex(@"(^|\s)[-/]e(c|n[a-z]*)?\s+[A-Za-z0-9+/=]{16,}", RegexOptions.IgnoreCase)]
    private static partial Regex EncodedArgRegex();

    [GeneratedRegex(@"[A-Za-z0-9+/]{100,}={0,2}")]
    private static partial Regex LongBase64Regex();
}
