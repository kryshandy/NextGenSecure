using System.Text;

namespace CoreGuard.Service;

/// <summary>Un fichier d'identifiants surveillé.</summary>
/// <param name="Browser">Famille de navigateur (Chrome, Edge, Brave, Firefox, Chromium-leurre).</param>
/// <param name="Honeypot">Vrai pour le faux profil Chromium : aucun logiciel légitime ne le lit.</param>
public sealed record CredentialFile(string Path, string Browser, bool Honeypot);

/// <summary>
/// Inventaire des fichiers que visent les voleurs d'identifiants (« infostealers ») dans un profil Windows,
/// et création d'un profil leurre Chromium (les voleurs essaient tous les chemins de navigateurs connus).
/// </summary>
public static class CredentialTargets
{
    public const string HoneypotMarker = "CoreGuard-HONEYPOT";

    // Navigateurs Chromium : dossier « User Data » relatif à %LOCALAPPDATA%
    private static readonly (string Browser, string UserData)[] Chromium =
    [
        ("Chrome", @"Google\Chrome\User Data"),
        ("Edge", @"Microsoft\Edge\User Data"),
        ("Brave", @"BraveSoftware\Brave-Browser\User Data")
    ];

    // Fichiers sensibles d'un profil Chromium (mots de passe, cookies de session, cartes bancaires)
    private static readonly string[] ChromiumProfileFiles = ["Login Data", @"Network\Cookies", "Cookies", "Web Data"];

    // Fichiers sensibles d'un profil Firefox (%APPDATA%\Mozilla\Firefox\Profiles\*)
    private static readonly string[] FirefoxFiles = ["logins.json", "key4.db", "cookies.sqlite"];

    /// <summary>Fichiers d'identifiants existants pour un profil Windows (racine C:\Users\nom).</summary>
    public static List<CredentialFile> Enumerate(string profileRoot)
    {
        var result = new List<CredentialFile>();
        string local = Path.Combine(profileRoot, "AppData", "Local");
        string roaming = Path.Combine(profileRoot, "AppData", "Roaming");

        foreach (var (browser, relative) in Chromium)
            AddChromium(result, Path.Combine(local, relative), browser, honeypot: false);

        string honeypot = Path.Combine(local, @"Chromium\User Data");
        if (IsHoneypot(honeypot))
            AddChromium(result, honeypot, "Chromium (leurre)", honeypot: true);

        string firefoxProfiles = Path.Combine(roaming, @"Mozilla\Firefox\Profiles");
        if (Directory.Exists(firefoxProfiles))
            foreach (string dir in SafeDirectories(firefoxProfiles))
                foreach (string f in FirefoxFiles)
                    AddIfExists(result, Path.Combine(dir, f), "Firefox", false);

        return result;
    }

    private static void AddChromium(List<CredentialFile> result, string userData, string browser, bool honeypot)
    {
        if (!Directory.Exists(userData)) return;
        AddIfExists(result, Path.Combine(userData, "Local State"), browser, honeypot);
        foreach (string dir in SafeDirectories(userData))
        {
            string name = Path.GetFileName(dir);
            if (name != "Default" && !name.StartsWith("Profile ", StringComparison.Ordinal)) continue;
            foreach (string f in ChromiumProfileFiles)
                AddIfExists(result, Path.Combine(dir, f), browser, honeypot);
        }
    }

    private static void AddIfExists(List<CredentialFile> result, string path, string browser, bool honeypot)
    {
        if (File.Exists(path)) result.Add(new CredentialFile(path, browser, honeypot));
    }

    private static IEnumerable<string> SafeDirectories(string root)
    {
        try { return Directory.GetDirectories(root); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>Vrai si le dossier « User Data » est NOTRE leurre (et non un vrai Chromium installé).</summary>
    public static bool IsHoneypot(string userData)
    {
        string state = Path.Combine(userData, "Local State");
        try { return File.Exists(state) && File.ReadAllText(state).Contains(HoneypotMarker, StringComparison.Ordinal); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>
    /// Crée le profil leurre Chromium dans %LOCALAPPDATA% du profil donné, sauf si un vrai Chromium est installé
    /// (dossier existant sans notre marqueur : on n'y touche jamais). Renvoie le dossier « User Data » du leurre, ou null.
    /// </summary>
    public static string? EnsureHoneypot(string profileRoot)
    {
        string userData = Path.Combine(profileRoot, @"AppData\Local\Chromium\User Data");
        if (Directory.Exists(userData) && !IsHoneypot(userData)) return null; // vrai Chromium : pas de leurre
        if (!Directory.Exists(Path.Combine(profileRoot, @"AppData\Local"))) return null;

        try
        {
            Directory.CreateDirectory(Path.Combine(userData, "Default"));
            File.WriteAllText(Path.Combine(userData, "Local State"),
                $"{{\"os_crypt\":{{\"encrypted_key\":\"{Convert.ToBase64String(Encoding.ASCII.GetBytes("DPAPI" + Guid.NewGuid().ToString("N")))}\"}},\"_marker\":\"{HoneypotMarker}\"}}");
            // En-tête SQLite (comme une vraie base « Login Data ») suivi du marqueur, aucune donnée réelle
            byte[] header = Encoding.ASCII.GetBytes("SQLite format 3\0");
            File.WriteAllBytes(Path.Combine(userData, @"Default\Login Data"),
                [.. header, .. Encoding.ASCII.GetBytes($"\n{HoneypotMarker} : faux profil leurre CoreGuard, aucun identifiant\n")]);
            return userData;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Supprime le leurre (uniquement s'il porte notre marqueur).</summary>
    public static void RemoveHoneypot(string profileRoot)
    {
        string chromium = Path.Combine(profileRoot, @"AppData\Local\Chromium");
        string userData = Path.Combine(chromium, "User Data");
        if (!IsHoneypot(userData)) return;
        try { Directory.Delete(chromium, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* best-effort */ }
    }
}
