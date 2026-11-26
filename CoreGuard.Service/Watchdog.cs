using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;

namespace CoreGuard.Service;

/// <summary>
/// Signal d'arrêt légitime envoyé par le service à son watchdog, sur l'entrée standard de ce dernier
/// (canal anonyme privé entre les deux processus). Format : « STOP &lt;horodatage ms&gt; &lt;HMAC hex&gt; »,
/// HMAC-SHA256 calculé avec une clé de session aléatoire transmise au lancement du watchdog.
/// </summary>
public static class WatchdogSignal
{
    public static readonly TimeSpan MaxSkew = TimeSpan.FromSeconds(60);

    public static string Sign(byte[] key, DateTimeOffset now)
    {
        string ts = now.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture);
        return $"STOP {ts} {Mac(key, ts)}";
    }

    public static bool Verify(byte[] key, string? line, DateTimeOffset now)
    {
        if (line is null) return false;
        string[] parts = line.Trim().Split(' ');
        if (parts.Length != 3 || parts[0] != "STOP" || !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out long ms))
            return false;
        if ((now - DateTimeOffset.FromUnixTimeMilliseconds(ms)).Duration() > MaxSkew) return false;

        byte[] expected = Encoding.ASCII.GetBytes(Mac(key, parts[1]));
        byte[] actual = Encoding.ASCII.GetBytes(parts[2]);
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    private static string Mac(byte[] key, string timestamp)
    {
        byte[] message = Encoding.ASCII.GetBytes("CoreGuard.Watchdog.Stop|" + timestamp);
        return Convert.ToHexString(HMACSHA256.HashData(key, message));
    }
}

/// <summary>
/// Côté service : lance le watchdog, le relance s'il disparaît, et le prévient avant un arrêt légitime.
/// Le watchdog surveille le service en retour (surveillance mutuelle) : tuer l'un fait relancer l'autre.
/// </summary>
public sealed class WatchdogSupervisor(ILogger<WatchdogSupervisor> logger) : IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly object _gate = new();
    private Process? _watchdog;
    private bool _stopping;
    private int _restarts;
    private DateTime _windowStart = DateTime.UtcNow;

    public int? WatchdogPid { get { lock (_gate) return _watchdog?.Id; } }

    /// <summary>Levé (PID) à chaque lancement du watchdog, pour l'ajouter aux processus protégés.</summary>
    public event EventHandler<int>? Started;

    public void Start(bool harden)
    {
        lock (_gate)
        {
            if (_stopping) return;
            string exe = Environment.ProcessPath ?? throw new InvalidOperationException("Chemin du service introuvable.");
            var psi = new ProcessStartInfo(exe)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true
            };
            psi.ArgumentList.Add("--watchdog");
            psi.ArgumentList.Add(Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
            if (harden) psi.ArgumentList.Add("--harden");
            if (!ServiceHost.IsWindowsService) psi.ArgumentList.Add("--console");

            var process = Process.Start(psi) ?? throw new InvalidOperationException("Lancement du watchdog impossible.");
            process.StandardInput.AutoFlush = true;
            process.StandardInput.WriteLine(Convert.ToHexString(_key));
            process.EnableRaisingEvents = true;
            process.Exited += (_, _) => OnWatchdogExited(harden);
            _watchdog = process;
            logger.LogInformation("Watchdog lancé (PID {Pid}).", process.Id);
            Started?.Invoke(this, process.Id);
        }
    }

    private void OnWatchdogExited(bool harden)
    {
        lock (_gate)
        {
            if (_stopping) return;
            // Anti-boucle : au plus 10 relances par minute
            if (DateTime.UtcNow - _windowStart > TimeSpan.FromMinutes(1)) { _windowStart = DateTime.UtcNow; _restarts = 0; }
            if (++_restarts > 10)
            {
                logger.LogError("Le watchdog s'arrête en boucle : relance suspendue pendant une minute.");
                _ = Task.Delay(TimeSpan.FromMinutes(1)).ContinueWith(_ =>
                {
                    try { Start(harden); }
                    catch (Exception ex) when (ex is not OutOfMemoryException) { logger.LogError("Relance du watchdog impossible : {Message}", ex.Message); }
                }, TaskScheduler.Default);
                return;
            }
        }
        logger.LogWarning("Watchdog arrêté de façon inattendue : relance.");
        try { Start(harden); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { logger.LogError("Relance du watchdog impossible : {Message}", ex.Message); }
    }

    /// <summary>Prévient le watchdog que l'arrêt qui suit est légitime (il ne relancera pas le service).</summary>
    public void SignalLegitimateStop()
    {
        lock (_gate)
        {
            _stopping = true;
            try { _watchdog?.StandardInput.WriteLine(WatchdogSignal.Sign(_key, DateTimeOffset.UtcNow)); }
            catch (Exception ex) when (ex is IOException or InvalidOperationException) { /* watchdog déjà parti */ }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _stopping = true;
            _watchdog?.Dispose();
            _watchdog = null;
        }
    }
}

/// <summary>Côté watchdog (même exécutable, lancé avec --watchdog &lt;pid&gt;).</summary>
public static partial class WatchdogRunner
{
    public static async Task<int> RunAsync(int servicePid, bool harden, bool console)
    {
        try
        {
            return await RunCoreAsync(servicePid, harden, console);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Log($"Erreur du watchdog : {ex.GetType().Name} — {ex.Message}");
            return 4;
        }
    }

    private static async Task<int> RunCoreAsync(int servicePid, bool harden, bool console)
    {
        string? keyHex = Console.ReadLine();
        if (keyHex is null) return 2;
        byte[] key = Convert.FromHexString(keyHex.Trim());

        if (harden)
        {
            var self = await new CoreGuard.Response.UserModeActionProvider().ProtectSelfAsync();
            Log(self.Message);
        }

        // SYNCHRONIZE seul : c'est le seul droit que la DACL durcie du service accorde aux autres processus
        // (System.Diagnostics.Process demanderait davantage et serait refusé)
        using SafeProcessHandle service = OpenProcess(Synchronize, false, servicePid);
        if (service.IsInvalid) { Log($"Service {servicePid} introuvable ou inaccessible (erreur {Marshal.GetLastPInvokeError()})."); return 3; }

        bool legitimate = false;
        _ = Task.Run(() =>
        {
            string? line;
            while ((line = Console.ReadLine()) is not null)
            {
                if (WatchdogSignal.Verify(key, line, DateTimeOffset.UtcNow)) { legitimate = true; Log("Arrêt légitime annoncé."); }
                else Log("Signal d'arrêt invalide ignoré.");
            }
        });

        await Task.Run(() => WaitForSingleObject(service, Infinite));
        await Task.Delay(500); // laisse arriver un éventuel signal écrit juste avant la sortie
        if (legitimate) { Log("Service arrêté légitimement : le watchdog se termine."); return 0; }

        Log($"Service {servicePid} arrêté sans autorisation : relance.");
        return Restart(harden, console) ? 0 : 1;
    }

    private static bool Restart(bool harden, bool console)
    {
        try
        {
            if (!console)
            {
                using var controller = new ServiceController(ServiceIdentity.ServiceName);
                if (controller.Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)
                {
                    controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
                    controller.Start();
                }
                return true;
            }

            // Mode console (développement) : relance du même exécutable, dans le même mode
            var psi = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            psi.ArgumentList.Add(harden ? "--harden" : "--supervise");
            Process.Start(psi)?.Dispose();
            return true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Log($"Relance impossible : {ex.Message}");
            return false;
        }
    }

    private const uint Synchronize = 0x00100000;
    private const uint Infinite = 0xFFFFFFFF;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    private static void Log(string message)
    {
        try
        {
            File.AppendAllText(Path.Combine(ServiceHost.DataDirectory, "watchdog.log"),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [PID {Environment.ProcessId}] {message}{Environment.NewLine}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* journal au mieux */ }
    }
}
