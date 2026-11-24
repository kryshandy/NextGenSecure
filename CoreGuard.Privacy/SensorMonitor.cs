using System.Runtime.Versioning;
using Microsoft.Win32;

namespace CoreGuard.Privacy;

/// <summary>Utilisation d'un capteur (caméra/micro) par un processus.</summary>
public sealed record SensorUsage(string Sensor, string Process, bool InUse, DateTime WhenUtc);

/// <summary>Configuration du moniteur de capteurs.</summary>
public sealed class SensorMonitorOptions
{
    /// <summary>Capteurs surveillés (noms de sous-clés du ConsentStore).</summary>
    public IReadOnlyList<string> Sensors { get; init; } = ["webcam", "microphone"];

    /// <summary>Intervalle de scrutation.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Liste blanche (nom d'exécutable, insensible à la casse) : usages non signalés.</summary>
    public ISet<string> Whitelist { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "teams.exe", "zoom.exe", "skype.exe" };
}

/// <summary>
/// Surveille le ConsentStore de Windows pour savoir quel processus utilise la caméra ou le micro.
/// Un capteur est « en cours d'utilisation » quand LastUsedTimeStop vaut 0 et LastUsedTimeStart &gt; 0.
/// Dégrade proprement : clés absentes ou inaccessibles = ignorées, jamais d'exception vers l'appelant.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SensorMonitor : IDisposable
{
    private const string BasePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    private readonly SensorMonitorOptions _options;
    private readonly Dictionary<string, bool> _lastState = new();
    private readonly object _gate = new();
    private System.Threading.Timer? _timer;

    public event EventHandler<SensorUsage>? UsageChanged;

    public SensorMonitor(SensorMonitorOptions? options = null) => _options = options ?? new();

    public void Start() => _timer ??= new System.Threading.Timer(_ => SafePoll(), null, TimeSpan.Zero, _options.PollInterval);

    public void Dispose() { _timer?.Dispose(); _timer = null; }

    /// <summary>Instantané de tous les usages actuellement actifs (hors liste blanche).</summary>
    public IReadOnlyList<SensorUsage> Snapshot() => ReadAll().Where(u => u.InUse && !IsWhitelisted(u.Process)).ToList();

    public bool IsWhitelisted(string process) =>
        _options.Whitelist.Contains(Path.GetFileName(process));

    private void SafePoll()
    {
        try { Poll(); } catch { /* dégradation silencieuse : le moniteur ne doit jamais planter l'hôte */ }
    }

    private void Poll()
    {
        List<SensorUsage> events = [];
        lock (_gate)
        {
            foreach (var u in ReadAll())
            {
                var key = u.Sensor + "|" + u.Process;
                _lastState.TryGetValue(key, out var was);
                if (was == u.InUse) continue;
                _lastState[key] = u.InUse;
                if (!IsWhitelisted(u.Process)) events.Add(u);
            }
        }
        foreach (var e in events) UsageChanged?.Invoke(this, e);
    }

    private IEnumerable<SensorUsage> ReadAll()
    {
        foreach (var sensor in _options.Sensors)
            foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
                foreach (var u in ReadHive(hive, sensor))
                    yield return u;
    }

    private static List<SensorUsage> ReadHive(RegistryHive hive, string sensor)
    {
        List<SensorUsage> result = [];
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = root.OpenSubKey($@"{BasePath}\{sensor}");
            if (key is null) return result;

            // Applications packagées (sous-clés directes) puis applications Win32 (NonPackaged).
            foreach (var name in key.GetSubKeyNames())
            {
                if (name == "NonPackaged") continue;
                AddIfValid(key, name, sensor, result);
            }
            using var np = key.OpenSubKey("NonPackaged");
            if (np is not null)
                foreach (var name in np.GetSubKeyNames())
                    AddIfValid(np, name, sensor, result);
        }
        catch { /* clé inaccessible : on dégrade */ }
        return result;
    }

    private static void AddIfValid(RegistryKey parent, string subName, string sensor, List<SensorUsage> into)
    {
        try
        {
            using var sub = parent.OpenSubKey(subName);
            if (sub is null) return;
            var start = sub.GetValue("LastUsedTimeStart") as long? ?? 0;
            var stop = sub.GetValue("LastUsedTimeStop") as long? ?? 0;
            into.Add(new SensorUsage(sensor, DecodeProcessName(subName), IsInUse(start, stop), DateTime.UtcNow));
        }
        catch { /* sous-clé illisible */ }
    }

    /// <summary>Pure : capteur actif si démarré et pas encore arrêté.</summary>
    public static bool IsInUse(long lastUsedStart, long lastUsedStop) => lastUsedStart > 0 && lastUsedStop == 0;

    /// <summary>Pure : les chemins NonPackaged encodent « \ » en « # ».</summary>
    public static string DecodeProcessName(string subKeyName) => subKeyName.Replace('#', '\\');
}
