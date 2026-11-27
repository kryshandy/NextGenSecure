using Microsoft.Win32;

namespace CoreGuard.Behavior;

public enum PersistenceRiskLevel { Low, Medium, High }

/// <summary>Évaluation d'une nouvelle entrée de démarrage.</summary>
public sealed record PersistenceAssessment(PersistenceRiskLevel Level, IReadOnlyList<string> Reasons)
{
    /// <summary>Résumé en une ligne (repli quand l'IA locale n'est pas disponible).</summary>
    public string Summary => Reasons.Count == 0
        ? "Programme installé dans un dossier d'applications, sans signe particulier."
        : char.ToUpperInvariant(Reasons[0][0]) + string.Join(" ; ", Reasons)[1..] + ".";
}

/// <summary>
/// Évaluation déterministe du risque d'une persistance (logique pure, testable). Les signaux sont ceux des
/// malwares courants : exécutable dans un dossier temporaire ou de téléchargement, interpréteur de script,
/// commande encodée, binaire système détourné (LOLBins), téléchargement au démarrage.
/// </summary>
public static class PersistenceRisk
{
    private static readonly string[] UserWritableFolders =
        [@"\appdata\local\temp\", @"\temp\", @"\downloads\", @"\téléchargements\", @"\users\public\", @"\programdata\", @"\appdata\roaming\"];

    private static readonly string[] ScriptHosts = ["powershell", "pwsh", "wscript", "cscript", "cmd.exe", "cmd /", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta"];

    private static readonly string[] Lolbins = ["mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msbuild", "installutil", "wmic"];

    public static PersistenceAssessment Assess(string kind, string command)
    {
        var reasons = new List<string>();
        int score = 0;
        string lower = (command ?? string.Empty).ToLowerInvariant();

        if (UserWritableFolders.Any(lower.Contains))
        {
            score += 2;
            reasons.Add("le programme se trouve dans un dossier temporaire, de téléchargement ou de données utilisateur");
        }
        if (ScriptHosts.Any(lower.Contains))
        {
            score += 2;
            reasons.Add("le démarrage lance un script (PowerShell, cmd, VBScript…)");
        }
        if (Lolbins.Any(l => lower.Contains(l)))
        {
            score += 2;
            reasons.Add("il détourne un outil système souvent utilisé par les malwares (mshta, rundll32, certutil…)");
        }
        if (lower.Contains("-enc") || lower.Contains("frombase64string") || lower.Contains("-e ") && lower.Contains("powershell"))
        {
            score += 3;
            reasons.Add("la commande est encodée (contenu volontairement illisible)");
        }
        if (lower.Contains("http://") || lower.Contains("https://") || lower.Contains("downloadstring") || lower.Contains("invoke-webrequest"))
        {
            score += 2;
            reasons.Add("il télécharge quelque chose depuis Internet à chaque démarrage");
        }
        if (lower.Contains("-windowstyle hidden") || lower.Contains("-w hidden"))
        {
            score += 1;
            reasons.Add("la fenêtre est volontairement masquée");
        }
        if (kind == "Service")
        {
            score += 1;
            reasons.Add("un nouveau service Windows démarre avec les droits système");
        }

        var level = score >= 4 ? PersistenceRiskLevel.High : score >= 2 ? PersistenceRiskLevel.Medium : PersistenceRiskLevel.Low;
        return new PersistenceAssessment(level, reasons);
    }
}

/// <summary>Résultat d'un blocage de persistance.</summary>
public sealed record PersistenceRemoval(bool Removed, string Message);

/// <summary>
/// Retrait d'une persistance bloquée par l'utilisateur. Les fichiers du dossier Démarrage ne sont pas supprimés
/// ici : l'appelant les met en quarantaine (restaurables). Les entrées système (HKLM, services) exigent les droits
/// administrateur ; sans eux, le retrait échoue proprement avec un message.
/// </summary>
public static class PersistenceRemover
{
    public static PersistenceRemoval Remove(PersistenceEvent evt)
    {
        try
        {
            switch (evt.Kind)
            {
                case "RunKey":
                    return RemoveRunValue(evt.Target);
                case "ScheduledTask":
                    return ScheduledTasks.Delete(evt.Target, out string? error)
                        ? new PersistenceRemoval(true, $"Tâche planifiée {evt.Target} supprimée.")
                        : new PersistenceRemoval(false, $"Suppression de la tâche impossible : {error}.");
                case "Service":
                    return RemoveService(evt.Target);
                default:
                    return new PersistenceRemoval(false, "Type d'entrée non pris en charge ici.");
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new PersistenceRemoval(false, "Droits administrateur requis pour retirer cette entrée.");
        }
    }

    /// <summary>« CurrentUser\\SOFTWARE\\...\\Run\\Nom » → suppression de la valeur Nom.</summary>
    internal static PersistenceRemoval RemoveRunValue(string target)
    {
        int first = target.IndexOf('\\'), last = target.LastIndexOf('\\');
        if (first <= 0 || last <= first) return new PersistenceRemoval(false, "Entrée de registre illisible.");
        if (!Enum.TryParse(target[..first], out RegistryHive hive)) return new PersistenceRemoval(false, "Ruche de registre inconnue.");
        string path = target[(first + 1)..last];
        string name = target[(last + 1)..];

        using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        using var key = root.OpenSubKey(path, writable: true);
        if (key?.GetValue(name) is null) return new PersistenceRemoval(false, "Entrée déjà absente.");
        key.DeleteValue(name);
        return new PersistenceRemoval(true, $"Lancement automatique « {name} » supprimé.");
    }

    private static PersistenceRemoval RemoveService(string name)
    {
        using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("sc.exe", $"delete \"{name}\"")
        { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
        p!.WaitForExit(10_000);
        return p.ExitCode == 0
            ? new PersistenceRemoval(true, $"Service {name} supprimé (il disparaîtra au prochain redémarrage s'il tourne encore).")
            : new PersistenceRemoval(false, p.ExitCode == 5 ? "Droits administrateur requis pour supprimer un service." : $"Suppression du service impossible (code {p.ExitCode}).");
    }
}
