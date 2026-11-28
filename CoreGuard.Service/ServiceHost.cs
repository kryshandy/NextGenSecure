using System.Runtime.Versioning;
using System.ServiceProcess;
using CoreGuard.Ipc;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;

namespace CoreGuard.Service;

/// <summary>Contexte d'exécution du service et emplacement de ses données.</summary>
public static class ServiceHost
{
    public static bool IsWindowsService { get; } = WindowsServiceHelpers.IsWindowsService();

    /// <summary>Mode développement explicite (CLI --dev ou service lancé en console).</summary>
    public static bool DevMode { get; set; }

    /// <summary>
    /// Données du service. En service Windows : %ProgramData%\CoreGuard (ACL réservées à SYSTEM et aux
    /// Administrateurs pour le secret). En console (développement) : %LocalAppData%\CoreGuard\service-dev.
    /// </summary>
    public static string DataDirectory
    {
        get
        {
            string dir = IsWindowsService || !DevMode
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CoreGuard")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CoreGuard", "service-dev");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>Vrai quand l'hôte tourne en console (pas sous le gestionnaire de services).</summary>
    public static bool IsConsoleRun { get; set; }

    public static string SecretPath => Path.Combine(DataDirectory, "protection.json");
    public static string LockdownStatePath => Path.Combine(DataDirectory, "lockdown.json");
    public static string ParanoiaStatePath => Path.Combine(DataDirectory, "paranoia.json");
    public static string RemoteControlPath => Path.Combine(DataDirectory, "remote-control.json");
    public static string RemoteLockPath => Path.Combine(DataDirectory, "remote-lock.json");

    /// <summary>Pipe utilisé : celui du service installé, ou celui de développement (console / --dev).</summary>
    public static string PipeName => IsWindowsService || !DevMode ? IpcContract.PipeName : IpcContract.DevPipeName;
}

/// <summary>Options de démarrage de l'hôte.</summary>
/// <param name="Harden">DACL de processus durcie (service et watchdog).</param>
/// <param name="Supervise">Watchdog mutuel actif.</param>
public sealed record ServiceOptions(bool Harden, bool Supervise);

/// <summary>
/// Cycle de vie du service Windows qui REFUSE l'arrêt par le gestionnaire de services (sc stop, Stop-Service,
/// services.msc) : seul un arrêt authentifié par mot de passe (pipe + HMAC) ou l'arrêt de Windows l'interrompt.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectedServiceLifetime : WindowsServiceLifetime
{
    public ProtectedServiceLifetime(IHostEnvironment environment, IHostApplicationLifetime applicationLifetime,
        ILoggerFactory loggerFactory, IOptions<HostOptions> optionsAccessor, IOptions<WindowsServiceLifetimeOptions> windowsServiceOptionsAccessor)
        : base(environment, applicationLifetime, loggerFactory, optionsAccessor, windowsServiceOptionsAccessor)
    {
        CanStop = false;
        CanShutdown = true;
    }

    protected override void OnShutdown()
    {
        // Arrêt de Windows : légitime
        base.OnShutdown();
    }
}

/// <summary>Commandes en ligne : définition du mot de passe et arrêt authentifié.</summary>
public static class ServiceCli
{
    /// <summary>--set-password : écrit le secret (nécessite l'administrateur hors --dev).</summary>
    public static int SetPassword()
    {
        if (!ServiceHost.DevMode && !Environment.IsPrivilegedProcess)
        {
            Console.Error.WriteLine("Droits administrateur requis pour définir le mot de passe de protection.");
            return 5;
        }

        string first = ReadSecret("Nouveau mot de passe de protection (8 caractères minimum) : ");
        string second = ReadSecret("Confirmation : ");
        if (first != second) { Console.Error.WriteLine("Les mots de passe ne correspondent pas."); return 2; }

        try
        {
            ProtectionSecret.Create(first).Save(ServiceHost.SecretPath, restrictToAdmins: !ServiceHost.DevMode);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
        Console.WriteLine($"Mot de passe de protection enregistré ({ServiceHost.SecretPath}).");
        Console.WriteLine("Redémarrez le service pour qu'il le prenne en compte s'il tourne déjà.");
        return 0;
    }

    /// <summary>
    /// --set-remote-lock &lt;dossier&gt; [&lt;dossier&gt;…] : active le verrouillage à distance par dossier synchronisé
    /// (administrateur hors --dev). Le code n'est conservé que sous forme d'empreinte PBKDF2.
    /// </summary>
    public static int SetRemoteLock(IReadOnlyList<string> folders)
    {
        if (!ServiceHost.DevMode && !Environment.IsPrivilegedProcess)
        {
            Console.Error.WriteLine("Droits administrateur requis pour configurer le verrouillage à distance.");
            return 5;
        }
        var existing = folders.Where(Directory.Exists).Select(Path.GetFullPath).ToList();
        if (existing.Count == 0) { Console.Error.WriteLine(@"Aucun dossier existant indiqué (ex. C:\Users\vous\OneDrive\CoreGuard)."); return 2; }

        string code = ReadSecret($"Code de verrouillage à distance ({RemoteLockConfig.MinCodeLength} caractères minimum) : ");
        string again = ReadSecret("Confirmation : ");
        if (code != again) { Console.Error.WriteLine("Les codes ne correspondent pas."); return 2; }
        try
        {
            RemoteLockConfig.Create(existing, code).Save(ServiceHost.RemoteLockPath, restrictToAdmins: !ServiceHost.DevMode);
        }
        catch (ArgumentException ex) { Console.Error.WriteLine(ex.Message); return 2; }

        Console.WriteLine("Verrouillage à distance configuré. Pour verrouiller le PC depuis votre téléphone : dans l'un de ces dossiers,");
        Console.WriteLine($"créez un fichier « {RemoteLockConfig.CommandFilePrefix}.txt » contenant uniquement votre code.");
        foreach (string f in existing) Console.WriteLine("  - " + f);
        Console.WriteLine("Redémarrez le service pour activer la surveillance.");
        return 0;
    }

    /// <summary>--stop : demande l'arrêt au service en cours d'exécution (défi-réponse HMAC).</summary>
    public static async Task<int> StopAsync()
    {
        await using var client = new ServiceClient(ServiceHost.PipeName, requireServiceSession: !ServiceHost.DevMode);
        if (!await client.ConnectAsync(TimeSpan.FromSeconds(5)))
        {
            Console.Error.WriteLine("Service CoreGuard injoignable.");
            return 3;
        }

        string password = ReadSecret("Mot de passe de protection : ");
        StopResult result = await client.RequestStopAsync(password);
        (result.Accepted ? Console.Out : Console.Error).WriteLine(result.Message);
        return result.Accepted ? 0 : 1;
    }

    // Saisie masquée en console ; lecture de ligne simple si l'entrée est redirigée (scripts)
    private static string ReadSecret(string prompt)
    {
        Console.Write(prompt);
        if (Console.IsInputRedirected) { Console.WriteLine(); return Console.ReadLine() ?? ""; }

        var sb = new System.Text.StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0) { sb.Length--; Console.Write("\b \b"); }
                continue;
            }
            // Un astérisque par caractère : l'utilisateur voit que la saisie est prise en compte
            if (!char.IsControl(key.KeyChar)) { sb.Append(key.KeyChar); Console.Write('*'); }
        }
        Console.WriteLine();
        return sb.ToString();
    }
}
