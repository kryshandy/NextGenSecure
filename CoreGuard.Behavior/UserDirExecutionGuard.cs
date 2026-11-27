using System.Collections.Concurrent;
using System.Diagnostics;

namespace CoreGuard.Behavior;

/// <summary>
/// Politique « pas d'exécutable non signé depuis les dossiers de l'utilisateur » (logique pure, testable) : la grande
/// majorité des malwares s'exécutent depuis Téléchargements, %TEMP%, %APPDATA% ou C:\Users\Public, alors que les
/// logiciels légitimes y sont presque toujours signés (installés ailleurs, ou signés s'ils vivent dans AppData).
/// </summary>
public static class UserDirExecutionPolicy
{
    /// <summary>Outils Windows légitimes très utilisés par les malwares pour télécharger ou exécuter du code distant.</summary>
    public static readonly string[] NetworkLolbins = ["mshta.exe", "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "wscript.exe", "cscript.exe"];

    private static readonly string[] UserWritableMarkers =
        [@"\downloads\", @"\téléchargements\", @"\appdata\local\temp\", @"\appdata\roaming\", @"\users\public\", @"\windows\temp\"];

    /// <summary>Vrai si le chemin est dans un dossier où un utilisateur (ou un malware) peut écrire sans droits.</summary>
    public static bool IsUserWritable(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string p = path.Replace('/', '\\').ToLowerInvariant();
        return UserWritableMarkers.Any(p.Contains);
    }

    /// <summary>Bloquer ? Exécutable non signé (ou signature invalide) lancé depuis un dossier de l'utilisateur.</summary>
    public static bool ShouldBlock(string? imagePath, bool trustedSignature) =>
        IsUserWritable(imagePath) && !trustedSignature;
}

/// <summary>Processus arrêté par le Mode Paranoïa.</summary>
public sealed record BlockedExecution(int Pid, string ImagePath, bool Terminated, DateTime WhenUtc);

/// <summary>
/// Applique <see cref="UserDirExecutionPolicy"/> aux processus qui démarrent. Deux sources possibles :
/// le service (ETW, en temps réel, droits SYSTEM) via <see cref="OnProcessStarted"/>, ou, sans service,
/// une scrutation de la liste des processus (<see cref="StartPolling"/>, sans droits administrateur).
/// </summary>
public sealed class UserDirExecutionGuard : IDisposable
{
    private readonly Func<string, bool> _isTrustedSigned;
    private readonly Func<int, bool> _terminate;
    private readonly Func<int, string?> _imagePath;
    private readonly ConcurrentDictionary<int, byte> _seen = new();
    private readonly HashSet<int> _excluded;
    private System.Threading.Timer? _poll;

    public UserDirExecutionGuard(Func<string, bool> isTrustedSigned, Func<int, bool> terminate, Func<int, string?> imagePath, IEnumerable<int>? excludedPids = null)
    {
        _isTrustedSigned = isTrustedSigned;
        _terminate = terminate;
        _imagePath = imagePath;
        _excluded = [.. excludedPids ?? [], Environment.ProcessId];
    }

    /// <summary>Levé pour chaque exécution bloquée (thread quelconque).</summary>
    public event Action<BlockedExecution>? Blocked;

    /// <summary>Nombre de processus arrêtés depuis l'activation.</summary>
    public int BlockedCount { get; private set; }

    /// <summary>Événement de démarrage de processus (ETW) : l'image est relue depuis le PID (ETW ne donne que le nom court).</summary>
    public void OnProcessStarted(int pid, string? imageHint = null)
    {
        if (_excluded.Contains(pid) || !_seen.TryAdd(pid, 0)) return;
        string? image = _imagePath(pid) ?? imageHint;
        if (!UserDirExecutionPolicy.IsUserWritable(image)) return;
        if (!UserDirExecutionPolicy.ShouldBlock(image, SafeTrusted(image!))) return;

        bool terminated = SafeTerminate(pid);
        BlockedCount++;
        Blocked?.Invoke(new BlockedExecution(pid, image!, terminated, DateTime.UtcNow));
    }

    /// <summary>Sans service : relit la liste des processus toutes les <paramref name="interval"/>. Les processus déjà lancés sont ignorés.</summary>
    public void StartPolling(TimeSpan interval)
    {
        foreach (var p in Process.GetProcesses()) { _seen.TryAdd(p.Id, 0); p.Dispose(); } // existants : on ne tue pas l'existant
        _poll = new System.Threading.Timer(_ =>
        {
            foreach (var p in Process.GetProcesses())
            {
                using (p) OnProcessStarted(p.Id);
            }
            // Les PID réutilisés par Windows doivent pouvoir être réexaminés
            if (_seen.Count > 20_000) _seen.Clear();
        }, null, interval, interval);
    }

    private bool SafeTrusted(string image)
    {
        try { return _isTrustedSigned(image); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return false; }
    }

    private bool SafeTerminate(int pid)
    {
        try { return _terminate(pid); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return false; }
    }

    public void Dispose()
    {
        _poll?.Dispose();
        _poll = null;
    }
}
