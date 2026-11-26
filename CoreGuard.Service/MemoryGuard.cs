using AntivirusIA.Core.Interfaces;
using CoreGuard.Memory;

namespace CoreGuard.Service;

/// <summary>
/// Scan mémoire périodique (menaces « fileless ») :
/// - image PE complète en mémoire privée exécutable → ARRÊT du processus hôte (le code injecté meurt avec lui) ;
/// - région privée RWX sans en-tête PE → simplement comptée (signal faible : fréquent chez des programmes légitimes).
/// En mode utilisateur, on arrête le processus qui HÉBERGE le code injecté ; l'injecteur, s'il est encore actif,
/// est un autre processus (ETW Threat-Intelligence / driver nécessaires pour l'identifier de façon certaine).
/// </summary>
public sealed class MemoryGuard(
    IKernelActionProvider actions,
    Action<string, string, string, string> publish,
    Func<ISet<int>> excludedPids,
    ILogger logger) : IDisposable
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan FirstScanDelay = TimeSpan.FromSeconds(20);

    private readonly CancellationTokenSource _cts = new();
    private Timer? _timer;
    private int _running;

    public DateTime? LastScanUtc { get; private set; }
    public MemoryScanSummary? LastSummary { get; private set; }
    public int ProcessesStopped { get; private set; }

    public string StatusText => LastSummary is { } s
        ? $"Dernier scan {LastScanUtc:HH:mm:ss} UTC : {s.ProcessesScanned} processus, {s.RegionsExamined} régions, "
          + $"{s.Suspicious.Count(r => r.Findings.All(f => f.Kind == MemoryFindingKind.PrivateRwx))} avec mémoire RWX (information) ; "
          + $"{ProcessesStopped} processus arrêté(s) depuis le démarrage"
        : "Premier scan dans quelques secondes";

    public void Start() => _timer = new Timer(_ => Scan(), null, FirstScanDelay, Interval);

    /// <summary>Lance un scan (ignoré si le précédent n'est pas terminé).</summary>
    public void Scan()
    {
        if (Interlocked.Exchange(ref _running, 1) == 1) return;
        try
        {
            MemoryScanSummary summary = ProcessMemoryScanner.ScanAll(excludedPids(), _cts.Token);
            LastScanUtc = DateTime.UtcNow;
            LastSummary = summary;
            foreach (var report in summary.Suspicious) Respond(report);
        }
        catch (OperationCanceledException)
        {
            // arrêt du service
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogWarning("Scan mémoire interrompu : {Message}", ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _running, 0);
        }
    }

    private void Respond(ProcessMemoryReport report)
    {
        var pe = report.Findings.FirstOrDefault(f => f.Kind == MemoryFindingKind.PeInPrivateMemory);
        if (pe is not null)
        {
            ActionResult result = actions.TerminateProcessAsync(report.Pid,
                $"exécutable chargé en mémoire privée à 0x{pe.BaseAddress:X} (injection / chargement réflectif)").GetAwaiter().GetResult();
            if (result.Success) ProcessesStopped++;
            publish(result.Success ? "Critical" : "Warning", "Mémoire",
                result.Success ? $"Code injecté : {report.ProcessName} arrêté" : $"Code injecté dans {report.ProcessName} (arrêt impossible)",
                $"{report.ProcessName} (PID {report.Pid}) contient une image PE hors de tout fichier, à 0x{pe.BaseAddress:X} ({pe.Size / 1024} Ko). {result.Message}");
            logger.LogWarning("Injection mémoire dans {Name} (PID {Pid}) à 0x{Base:X} : {Message}", report.ProcessName, report.Pid, pe.BaseAddress, result.Message);
            return;
        }

        // RWX seul : signal trop faible pour alerter. Mesuré sur un poste réel, une quinzaine de programmes légitimes
        // (MSBuild, WhatsApp, Explorer, Python, pilotes graphiques…) en possèdent : on se contente de les compter.
    }

    public void Dispose()
    {
        _cts.Cancel();
        _timer?.Dispose();
        _cts.Dispose();
    }
}
