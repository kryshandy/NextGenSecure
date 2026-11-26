using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace CoreGuard.Privacy;

/// <summary>Résultat d'une coupure de capteur.</summary>
public sealed record SensorCutResult(int ProcessesStopped, bool AccessDenied, string Message);

/// <summary>
/// Coupure de la caméra / du micro. Deux leviers, combinés par <see cref="Cut"/> :
/// - arrêt des processus de l'application qui utilise le capteur (effet immédiat) ;
/// - refus d'accès dans les paramètres de confidentialité Windows (ConsentStore) pour qu'elle ne le reprenne pas.
/// LIMITE Windows : le refus par application n'existe que pour les applications du Store (packagées) ; pour les
/// applications de bureau, Windows n'offre qu'un interrupteur global « applications de bureau »
/// (<see cref="SetDesktopAppsAccess"/>).
/// </summary>
public static partial class SensorControl
{
    private const string ConsentStore = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    /// <summary>Vrai si l'usage provient d'une application de bureau (chemin d'exécutable) et non d'une app du Store.</summary>
    public static bool IsDesktopApp(string process) => process.Contains('\\') || process.Contains('/');

    /// <summary>Clé de consentement (HKCU) d'une application du Store ; null pour une application de bureau.</summary>
    public static string? PackagedConsentKey(string sensor, string process) =>
        IsDesktopApp(process) ? null : $@"{ConsentStore}\{sensor}\{process}";

    /// <summary>Clé de l'interrupteur global « applications de bureau » (HKCU).</summary>
    public static string DesktopAppsConsentKey(string sensor) => $@"{ConsentStore}\{sensor}\NonPackaged";

    /// <summary>Coupe le capteur pour cette application : arrêt de ses processus + refus d'accès si possible.</summary>
    public static SensorCutResult Cut(SensorUsage usage, Func<int, bool> terminate)
    {
        int stopped = 0;
        if (IsDesktopApp(usage.Process))
        {
            foreach (int pid in FindProcessesByImage(usage.Process))
                if (terminate(pid)) stopped++;
        }

        bool denied = false;
        if (PackagedConsentKey(usage.Sensor, usage.Process) is { } key)
            denied = SetConsent(key, allow: false);

        string app = Path.GetFileName(usage.Process);
        string message = (stopped, denied) switch
        {
            ( > 0, _) => $"{app} arrêté ({stopped} processus).",
            (0, true) => $"Accès au capteur retiré à {app}.",
            _ => $"{app} n'a pas pu être arrêté (déjà fermé, ou processus administrateur)."
        };
        if (IsDesktopApp(usage.Process))
            message += " Pour l'empêcher de recommencer : interdire ce capteur aux applications de bureau (Réglages).";
        return new SensorCutResult(stopped, denied, message);
    }

    /// <summary>Autorise ou interdit le capteur à TOUTES les applications de bureau (paramètre Windows de l'utilisateur).</summary>
    public static bool SetDesktopAppsAccess(string sensor, bool allow) => SetConsent(DesktopAppsConsentKey(sensor), allow);

    /// <summary>État de l'interrupteur « applications de bureau » (vrai = autorisé, valeur absente = autorisé).</summary>
    public static bool IsDesktopAppsAccessAllowed(string sensor)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(DesktopAppsConsentKey(sensor));
            return key?.GetValue("Value") as string is not "Deny";
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    private static bool SetConsent(string subKey, bool allow)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(subKey, writable: true);
            key.SetValue("Value", allow ? "Allow" : "Deny", RegistryValueKind.String);
            return true;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    /// <summary>PID des processus dont l'exécutable est exactement ce chemin (comparaison sans tenir compte de la casse).</summary>
    public static IReadOnlyList<int> FindProcessesByImage(string imagePath)
    {
        var result = new List<int>();
        string name = Path.GetFileNameWithoutExtension(imagePath);
        foreach (var p in Process.GetProcessesByName(name))
        {
            using (p)
            {
                string? path = ImagePath(p.Id);
                if (path is not null && string.Equals(path, imagePath, StringComparison.OrdinalIgnoreCase)) result.Add(p.Id);
            }
        }
        return result;
    }

    private static unsafe string? ImagePath(int pid)
    {
        using SafeProcessHandle h = OpenProcess(0x1000 /* QUERY_LIMITED_INFORMATION */, false, pid);
        if (h.IsInvalid) return null;
        char* buffer = stackalloc char[1024];
        uint size = 1024;
        return QueryFullProcessImageNameW(h, 0, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(int access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, char* buffer, ref uint size);
}
