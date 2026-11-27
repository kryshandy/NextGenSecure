using System.Diagnostics.Eventing.Reader;
using System.Xml;
using Microsoft.Win32;

namespace CoreGuard.Behavior;

/// <summary>
/// Mécanisme de persistance détecté. Kind : RunKey, ScheduledTask, StartupFolder ou Service.
/// Target identifie l'entrée pour pouvoir la retirer : « Hive\chemin\valeur », chemin de tâche (« \Nom »),
/// chemin du fichier du dossier Démarrage, ou nom du service.
/// </summary>
public sealed record PersistenceEvent(string Kind, string Target, string Command);

/// <summary>
/// Gardien de persistance : clés Run/RunOnce (sondage), tâches planifiées (sondage du dossier Tasks)
/// et services installés (journal Système, événement 7045). L'UI s'abonne à
/// <see cref="PersistenceDetected"/> pour proposer Autoriser/Bloquer.
/// </summary>
public sealed class PersistenceWatcher : IDisposable
{
    private const int MaxField = 1024;
    private const int MaxTaskFileBytes = 1_000_000;

    private static readonly (RegistryHive Hive, string Path)[] RunKeys =
    [
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ];

    private readonly TimeSpan _interval;
    private readonly string _tasksDir;
    private readonly object _lock = new();
    private Dictionary<string, string> _runSnapshot = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, string> _taskSnapshot = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, string> _startupSnapshot = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;
    private EventLogWatcher? _serviceWatcher;
    private int _polling;

    public PersistenceWatcher(TimeSpan? pollInterval = null, string? tasksDirectory = null)
    {
        _interval = pollInterval is { } p && p > TimeSpan.Zero ? p : TimeSpan.FromSeconds(5);
        _tasksDir = tasksDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
    }

    public bool IsRunning { get; private set; }

    /// <summary>Levé à chaque nouvelle persistance. Peut venir d'un thread d'arrière-plan.</summary>
    public event EventHandler<PersistenceEvent>? PersistenceDetected;

    /// <summary>Levé pour un avertissement non fatal (source indisponible, droits manquants).</summary>
    public event EventHandler<string>? Warning;

    public bool Start()
    {
        lock (_lock)
        {
            if (IsRunning) return true;

            // Instantané de référence : seuls les ajouts ultérieurs déclenchent un événement.
            _runSnapshot = ReadRunValues();
            _taskSnapshot = ReadTasks();
            _startupSnapshot = ReadStartupFiles();
            StartServiceWatcher();
            _timer = new Timer(_ => Poll(), null, _interval, _interval);
            IsRunning = true;
            return true;
        }
    }

    public void Stop()
    {
        lock (_lock)
        {
            _timer?.Dispose();
            _timer = null;
            if (_serviceWatcher is not null)
            {
                try { _serviceWatcher.Enabled = false; _serviceWatcher.Dispose(); } catch { /* best-effort */ }
                _serviceWatcher = null;
            }
            IsRunning = false;
        }
    }

    private void StartServiceWatcher()
    {
        try
        {
            var query = new EventLogQuery("System", PathType.LogName,
                "*[System[Provider[@Name='Service Control Manager'] and (EventID=7045)]]");
            var watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += OnServiceInstalled;
            watcher.Enabled = true;
            _serviceWatcher = watcher;
        }
        catch (Exception ex)
        {
            Warning?.Invoke(this, $"Surveillance des services (7045) indisponible : {ex.GetType().Name}");
        }
    }

    private void OnServiceInstalled(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            using var rec = e.EventRecord;
            if (rec is null || rec.Id != 7045) return;
            // Propriétés 7045 : [0] nom du service, [1] chemin de l'image, ...
            string name = Clean(rec.Properties.Count > 0 ? rec.Properties[0].Value?.ToString() : null);
            string path = Clean(rec.Properties.Count > 1 ? rec.Properties[1].Value?.ToString() : null);
            Raise(new PersistenceEvent("Service", name, path));
        }
        catch { /* événement illisible : ignoré */ }
    }

    private void Poll()
    {
        if (Interlocked.Exchange(ref _polling, 1) == 1) return;
        try
        {
            var runs = ReadRunValues();
            foreach (var (id, cmd) in runs)
            {
                if (!_runSnapshot.TryGetValue(id, out var old) || old != cmd)
                    Raise(new PersistenceEvent("RunKey", id, cmd));
            }
            _runSnapshot = runs;

            var tasks = ReadTasks();
            foreach (var (name, cmd) in tasks)
                if (!_taskSnapshot.ContainsKey(name))
                    Raise(new PersistenceEvent("ScheduledTask", Clean(name), cmd));
            _taskSnapshot = tasks;

            var startup = ReadStartupFiles();
            foreach (var (file, target) in startup)
                if (!_startupSnapshot.ContainsKey(file))
                    Raise(new PersistenceEvent("StartupFolder", Clean(file), target));
            _startupSnapshot = startup;
        }
        catch (Exception ex)
        {
            Warning?.Invoke(this, $"Échec du sondage de persistance : {ex.GetType().Name}");
        }
        finally { Volatile.Write(ref _polling, 0); }
    }

    private static Dictionary<string, string> ReadRunValues()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, path) in RunKeys)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(path);
                if (key is null) continue;
                foreach (var name in key.GetValueNames())
                    result[$"{hive}\\{path}\\{name}"] = Clean(key.GetValue(name)?.ToString());
            }
            catch { /* clé inaccessible : ignorée */ }
        }
        return result;
    }

    /// <summary>
    /// Tâches planifiées : nom (chemin « \Dossier\Nom ») → commande. Le dossier System32\Tasks n'est lisible que
    /// par les administrateurs : sans ces droits, on interroge le Planificateur de tâches (COM), qui liste les
    /// tâches visibles par l'utilisateur, dont celles qu'un programme malveillant aurait créées en son nom.
    /// </summary>
    private Dictionary<string, string> ReadTasks()
    {
        var fromFiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (Directory.Exists(_tasksDir))
                foreach (var f in Directory.EnumerateFiles(_tasksDir, "*", SearchOption.AllDirectories))
                    fromFiles["\\" + Path.GetRelativePath(_tasksDir, f)] = ReadTaskCommand(f);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            fromFiles.Clear(); // lecture partielle : on préfère le Planificateur
        }
        return fromFiles.Count > 0 ? fromFiles : ScheduledTasks.ReadAll();
    }

    /// <summary>Fichiers des dossiers Démarrage (utilisateur et commun) : chemin → nom affiché.</summary>
    private static Dictionary<string, string> ReadStartupFiles()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var folder in new[] { Environment.SpecialFolder.Startup, Environment.SpecialFolder.CommonStartup })
        {
            try
            {
                string dir = Environment.GetFolderPath(folder);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                foreach (var f in Directory.EnumerateFiles(dir))
                {
                    if (Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    result[f] = Clean(Path.GetFileName(f));
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { /* dossier inaccessible */ }
        }
        return result;
    }

    private static string ReadTaskCommand(string file)
    {
        try
        {
            var info = new FileInfo(file);
            if (!info.Exists || info.Length > MaxTaskFileBytes) return string.Empty;
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var reader = XmlReader.Create(file, settings);
            string? command = null;
            string? args = null;
            while (reader.Read())
            {
                if (reader.NodeType != XmlNodeType.Element) continue;
                if (reader.LocalName == "Command" && command is null) command = reader.ReadElementContentAsString();
                else if (reader.LocalName == "Arguments" && args is null) args = reader.ReadElementContentAsString();
                if (command is not null && args is not null) break;
            }
            return Clean($"{command} {args}".Trim());
        }
        catch { /* XML invalide ou illisible */ }
        return string.Empty;
    }

    private void Raise(PersistenceEvent evt)
    {
        try { PersistenceDetected?.Invoke(this, evt); }
        catch { /* un abonné défaillant ne doit pas casser la surveillance */ }
    }

    /// <summary>Assainit une donnée non fiable : contrôles supprimés, longueur bornée.</summary>
    private static string Clean(string? s) => BehaviorRuleEngine.Sanitize(s, MaxField);

    public void Dispose() => Stop();
}
