using System.Runtime.InteropServices;

namespace CoreGuard.Behavior;

/// <summary>
/// Accès au Planificateur de tâches Windows par COM (« Schedule.Service »), en liaison tardive : aucune assembly
/// d'interop. Liste les tâches visibles par le compte courant et peut en supprimer une.
/// </summary>
public static class ScheduledTasks
{
    private const int TaskActionExec = 0;
    private const int MaxTasks = 5000;

    /// <summary>Tâches visibles : chemin (« \\Dossier\\Nom ») → commande exécutée (chemin + arguments).</summary>
    public static Dictionary<string, string> ReadAll()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            dynamic service = CreateService();
            service.Connect();
            Walk(service.GetFolder("\\"), result);
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or UnauthorizedAccessException or IOException
                                       or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or ArgumentException)
        {
            // Planificateur indisponible : liste vide, la surveillance continue sur les autres sources
        }
        return result;
    }

    private static void Walk(dynamic folder, Dictionary<string, string> into)
    {
        if (into.Count >= MaxTasks) return;
        try
        {
            foreach (dynamic task in folder.GetTasks(1 /* inclure les tâches cachées */))
            {
                string path = task.Path;
                into[path] = Command(task);
                if (into.Count >= MaxTasks) return;
            }
            foreach (dynamic sub in folder.GetFolders(0)) Walk(sub, into);
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or IOException)
        {
            // dossier non lisible (tâches système d'un autre compte) : ignoré
        }
    }

    private static string Command(dynamic task)
    {
        try
        {
            foreach (dynamic action in task.Definition.Actions)
            {
                if ((int)action.Type != TaskActionExec) continue;
                string exe = action.Path ?? "";
                string args = action.Arguments ?? "";
                return BehaviorRuleEngine.Sanitize($"{exe} {args}".Trim(), 1024);
            }
        }
        catch (Exception ex) when (ex is COMException or IOException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException) { }
        return string.Empty;
    }

    /// <summary>Supprime une tâche par son chemin. Faux si elle est absente ou si les droits manquent.</summary>
    public static bool Delete(string taskPath, out string? error)
    {
        try
        {
            dynamic service = CreateService();
            service.Connect();
            int split = taskPath.LastIndexOf('\\');
            string folderPath = split <= 0 ? "\\" : taskPath[..split];
            string name = taskPath[(split + 1)..];
            dynamic folder = service.GetFolder(folderPath);
            folder.DeleteTask(name, 0);
            error = null;
            return true;
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or IOException or ArgumentException
                                       or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            error = ex is UnauthorizedAccessException || ex.HResult == unchecked((int)0x80070005) ? "droits administrateur requis"
                  : ex is FileNotFoundException || ex.HResult == unchecked((int)0x80070002) ? "tâche introuvable"
                  : ex.GetType().Name;
            return false;
        }
    }

    private static dynamic CreateService() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
}
