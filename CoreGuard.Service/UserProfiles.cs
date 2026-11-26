using System.Runtime.Versioning;
using Microsoft.Win32;

namespace CoreGuard.Service;

/// <summary>
/// Dossiers des utilisateurs à protéger par des canaris (Documents, Bureau, Images), vus depuis le service SYSTEM :
/// profils réels de la machine (SID S-1-5-21-…), dossiers éventuellement redirigés (« User Shell Folders »)
/// quand la ruche de l'utilisateur est chargée, sinon emplacements par défaut.
/// </summary>
[SupportedOSPlatform("windows")]
public static class UserProfiles
{
    private const string ProfileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    private const string ShellFoldersKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

    // Valeur de registre « User Shell Folders » → nom du dossier par défaut dans le profil
    private static readonly (string Value, string Default)[] Folders =
    [
        ("Personal", "Documents"), ("Desktop", "Desktop"), ("My Pictures", "Pictures")
    ];

    public static IReadOnlyList<string> CanaryFolders()
    {
        var result = new List<string>();
        using var list = Registry.LocalMachine.OpenSubKey(ProfileListKey);
        if (list is null) return result;

        foreach (string sid in list.GetSubKeyNames())
        {
            if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) continue; // comptes système exclus
            using var key = list.OpenSubKey(sid);
            if (key?.GetValue("ProfileImagePath") is not string rawProfile) continue;
            string profile = Environment.ExpandEnvironmentVariables(rawProfile);
            if (!Directory.Exists(profile)) continue;

            using var shell = Registry.Users.OpenSubKey($@"{sid}\{ShellFoldersKey}"); // null si l'utilisateur n'est pas connecté
            foreach (var (value, fallback) in Folders)
            {
                string? raw = shell?.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                string folder = (raw is null ? null : ExpandShellFolder(raw, profile)) ?? Path.Combine(profile, fallback);
                if (Directory.Exists(folder) && !result.Contains(folder, StringComparer.OrdinalIgnoreCase))
                    result.Add(folder);
            }
        }
        return result;
    }

    /// <summary>
    /// Développe un chemin « User Shell Folders » pour un profil donné. %USERPROFILE% vise le profil de
    /// l'utilisateur (et non celui du service) ; les autres variables sont développées normalement.
    /// Null si le résultat n'est pas un chemin absolu.
    /// </summary>
    internal static string? ExpandShellFolder(string raw, string profile)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        string replaced = raw.Replace("%USERPROFILE%", profile, StringComparison.OrdinalIgnoreCase);
        string expanded = Environment.ExpandEnvironmentVariables(replaced).Trim();
        return Path.IsPathFullyQualified(expanded) ? Path.TrimEndingDirectorySeparator(expanded) : null;
    }
}
