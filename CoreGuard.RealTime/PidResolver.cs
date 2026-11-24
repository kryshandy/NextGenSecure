using System.Diagnostics;

namespace CoreGuard.RealTime;

/// <summary>
/// Identification BEST-EFFORT du processus fautif.
/// LIMITE : en user-mode sans driver, Windows n'indique pas quel processus a écrit un fichier,
/// et FileSystemWatcher ne fournit pas le PID. Heuristique retenue : le processus non système
/// démarré le plus récemment (fenêtre courte), hors processus de confiance.
/// Le résultat est un SUSPECT, jamais une preuve ; null si rien de plausible.
/// Une identification fiable nécessitera ETW (Microsoft-Windows-Kernel-File) ou un minifilter (Phase 2).
/// </summary>
public static class PidResolver
{
    private static readonly HashSet<string> Ignores = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "System", "Idle", "svchost", "dwm", "csrss", "services", "lsass", "winlogon",
        "dotnet", "testhost", "devenv", "MsMpEng", "SearchIndexer", "SearchProtocolHost"
    };

    /// <summary>Retourne le PID du processus récent le plus plausible, ou null.</summary>
    public static int? FindSuspectPid(TimeSpan? window = null)
    {
        var limit = DateTime.Now - (window ?? TimeSpan.FromSeconds(60));
        int? best = null;
        var bestStart = DateTime.MinValue;
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                using (p)
                {
                    if (p.Id == Environment.ProcessId || Ignores.Contains(p.ProcessName)) continue;
                    var start = p.StartTime;
                    if (start >= limit && start > bestStart) { best = p.Id; bestStart = start; }
                }
            }
            catch { /* accès refusé / processus terminé : ignoré */ }
        }
        return best;
    }
}
