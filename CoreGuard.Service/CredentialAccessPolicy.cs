namespace CoreGuard.Service;

/// <summary>Décision pour un accès en lecture à un fichier d'identifiants.</summary>
public enum CredentialDecision { Allow, Stop }

/// <summary>Signature numérique de l'exécutable lecteur (résultat Authenticode).</summary>
public sealed record SignerInfo(bool Valid, string? Publisher);

/// <summary>
/// Qui a le droit de lire les fichiers d'identifiants des navigateurs (logique pure, testable) :
/// - un navigateur, reconnu à son NOM d'exécutable ET à sa signature valide par l'éditeur attendu (un faux
///   « chrome.exe » non signé par Google ne passe pas) ; un navigateur peut lire les fichiers d'un autre
///   (import des mots de passe) ;
/// - Microsoft Defender et l'indexation Windows, depuis leurs dossiers système ;
/// - personne pour le leurre Chromium (aucun Chromium installé) sauf Defender / indexation.
/// Tout autre lecteur (programme inconnu, script PowerShell, cmd /c copy…) est arrêté.
/// </summary>
public static class CredentialAccessPolicy
{
    private static readonly Dictionary<string, string[]> Browsers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["chrome.exe"] = ["Google"],
        ["msedge.exe"] = ["Microsoft"],
        ["brave.exe"] = ["Brave"],
        ["firefox.exe"] = ["Mozilla"],
        ["opera.exe"] = ["Opera"],
        ["vivaldi.exe"] = ["Vivaldi"]
    };

    private static readonly HashSet<string> SystemReaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "MsMpEng.exe", "MpDefenderCoreService.exe", "NisSrv.exe", "SearchIndexer.exe", "SearchProtocolHost.exe"
    };

    public static CredentialDecision Decide(string processImagePath, bool honeypot, SignerInfo signer)
    {
        string file = Path.GetFileName(processImagePath);

        if (SystemReaders.Contains(file) && IsInSystemLocation(processImagePath) && signer.Valid
            && signer.Publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true)
            return CredentialDecision.Allow;

        if (honeypot) return CredentialDecision.Stop;

        if (Browsers.TryGetValue(file, out string[]? publishers) && signer.Valid && signer.Publisher is { } p
            && publishers.Any(expected => p.Contains(expected, StringComparison.OrdinalIgnoreCase)))
            return CredentialDecision.Allow;

        return CredentialDecision.Stop;
    }

    /// <summary>Exécutable situé dans un dossier système (Windows, Defender) : non modifiable sans droits admin.</summary>
    internal static bool IsInSystemLocation(string path)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }

        string[] roots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender")
        ];
        return roots.Any(r => !string.IsNullOrEmpty(r)
            && full.StartsWith(Path.TrimEndingDirectorySeparator(r) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
    }
}
