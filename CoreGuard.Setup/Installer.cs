using System.Diagnostics;
using System.ServiceProcess;
using Microsoft.Win32;

namespace CoreGuard.Setup;

/// <summary>Choix de l'utilisateur dans l'assistant.</summary>
public sealed record InstallOptions(
    string? NewPassword,
    string? CurrentPassword,
    bool InstallService,
    bool InstallAmsi,
    bool InstallBrowserHost,
    bool DesktopShortcut);

/// <summary>
/// Installation hors ligne de CoreGuard depuis la charge utile (payload\) : application (avec le modèle d'IA local et
/// le modèle EMBER/ONNX), service SYSTEM, fournisseur AMSI, hôte de l'extension navigateur, raccourcis, entrée
/// « Applications installées ». Rien n'est téléchargé. Chaque étape est journalisée.
/// </summary>
public sealed class Installer(string payloadDir, Action<string> log)
{
    public const string ServiceName = "CoreGuardService";
    public const string AmsiClsid = "{6B3C2F1E-8A4D-4C7B-9E21-C0A5E9F4D317}";
    public const string NativeHostName = "com.coreguard.host";
    public const string ExtensionId = "dkmnbfljkgocbdiileppcmlcphbjbimi";
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CoreGuard";
    private static readonly string[] BrowserHostKeys =
    [
        @"SOFTWARE\Google\Chrome\NativeMessagingHosts", @"SOFTWARE\Microsoft\Edge\NativeMessagingHosts",
        @"SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts", @"SOFTWARE\Chromium\NativeMessagingHosts"
    ];

    public static string InstallDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CoreGuard");
    public static string AppExe => Path.Combine(InstallDir, "App", "AntivirusIA.UI.exe");
    public static string ServiceExe => Path.Combine(InstallDir, "Service", "CoreGuard.Service.exe");
    public static string ProtectionFile => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CoreGuard", "protection.json");

    public static bool ServiceExists => ServiceController.GetServices().Any(s => s.ServiceName == ServiceName);
    public static bool PasswordConfigured => File.Exists(ProtectionFile);

    /// <summary>Taille de la charge utile (affichée à l'accueil).</summary>
    public long PayloadBytes() =>
        Directory.Exists(payloadDir) ? new DirectoryInfo(payloadDir).EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length) : 0;

    public void Install(InstallOptions o, IProgress<int> progress)
    {
        if (!Directory.Exists(Path.Combine(payloadDir, "App")))
            throw new InvalidOperationException("Charge utile introuvable : lancez CoreGuard-Setup.exe depuis son dossier (à côté de « payload »).");

        progress.Report(5);
        StopRunning(o.CurrentPassword);
        progress.Report(15);

        InstallVcRuntime();

        log("Copie de l'application, du modèle d'IA local et du modèle EMBER/ONNX…");
        CopyDirectory(Path.Combine(payloadDir, "App"), Path.Combine(InstallDir, "App"));
        CopyModelFromSetupFolder();
        progress.Report(55);
        foreach (string part in new[] { "Docs", "Demo", "Extension" })
            if (Directory.Exists(Path.Combine(payloadDir, part))) CopyDirectory(Path.Combine(payloadDir, part), Path.Combine(InstallDir, part));
        CopySelf();
        progress.Report(62);

        if (o.InstallService) InstallServiceAndPassword(o);
        progress.Report(75);
        if (o.InstallAmsi) InstallAmsi();
        progress.Report(80);
        if (o.InstallService) StartService();
        progress.Report(88);
        if (o.InstallBrowserHost) InstallBrowserHost();
        progress.Report(93);
        CreateShortcuts(o.DesktopShortcut);
        RegisterUninstall();
        progress.Report(100);
        log("Installation terminée.");
    }

    public const string ModelFile = "Llama-3.2-3B-Instruct-Q4_K_M.gguf";

    /// <summary>Le modèle d'IA local est-il fourni (dans la charge utile ou à côté de l'installateur) ?</summary>
    public bool ModelAvailable() =>
        File.Exists(Path.Combine(payloadDir, "App", "models", ModelFile)) || File.Exists(Path.Combine(SetupFolder, ModelFile));

    private string SetupFolder => Path.GetDirectoryName(Path.GetFullPath(payloadDir))!;

    // Runtime C++ de Microsoft (ONNX Runtime, llama.cpp) : les DLL sont déjà à côté de l'application ; l'installateur
    // officiel est lancé en plus pour les autres programmes qui en dépendraient. 1638 = version plus récente déjà là.
    private void InstallVcRuntime()
    {
        string vcredist = Path.Combine(payloadDir, "Redist", "vc_redist.x64.exe");
        if (!File.Exists(vcredist)) return;
        log("Runtime Visual C++ (requis par l'IA locale)…");
        int code = Run(vcredist, "/install /quiet /norestart");
        log(code is 0 or 1638 or 3010 ? "   runtime Visual C++ présent." : $"   installateur Visual C++ : code {code} (les DLL locales de l'application suffisent).");
    }

    // Release GitHub : le modèle (2 Go) est un fichier séparé, placé à côté de CoreGuard-Setup.exe
    private void CopyModelFromSetupFolder()
    {
        string target = Path.Combine(InstallDir, "App", "models", ModelFile);
        if (File.Exists(target)) return;
        string beside = Path.Combine(SetupFolder, ModelFile);
        if (File.Exists(beside))
        {
            log("Copie du modèle d'IA local fourni à côté de l'installateur…");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(beside, target, overwrite: true);
        }
        else
        {
            log($"ATTENTION : modèle d'IA {ModelFile} absent. CoreGuard fonctionne, mais sans explications par l'IA : " +
                $"le placer plus tard dans {Path.GetDirectoryName(target)}.");
        }
    }

    // ---------------------------------------------------------------- arrêt de l'existant

    private void StopRunning(string? currentPassword)
    {
        foreach (var p in Process.GetProcessesByName("AntivirusIA.UI").Concat(Process.GetProcessesByName("CoreGuard.Extension")))
        {
            try { log($"Fermeture de {p.ProcessName} (PID {p.Id})…"); p.Kill(); p.WaitForExit(5000); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            finally { p.Dispose(); }
        }

        if (!ServiceExists) return;
        using var sc = new ServiceController(ServiceName);
        if (sc.Status == ServiceControllerStatus.Stopped) return;
        log("Arrêt du service CoreGuard existant (auto-défense : mot de passe de protection)…");
        if (File.Exists(ServiceExe) && currentPassword is not null)
        {
            int code = Run(ServiceExe, "--stop", stdin: currentPassword + "\n");
            if (code != 0) throw new InvalidOperationException("Le service a refusé l'arrêt : mot de passe de protection incorrect.");
        }
        else
        {
            try { sc.Stop(); } catch (InvalidOperationException) { }
        }
        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
    }

    // ---------------------------------------------------------------- service

    private void InstallServiceAndPassword(InstallOptions o)
    {
        log("Installation du service CoreGuard (LocalSystem, démarrage automatique)…");
        CopyDirectory(Path.Combine(payloadDir, "Service"), Path.Combine(InstallDir, "Service"));
        if (!ServiceExists)
        {
            Run("sc.exe", $"create {ServiceName} binPath= \"\\\"{ServiceExe}\\\"\" start= auto DisplayName= \"CoreGuard - Protection\"");
            Run("sc.exe", $"description {ServiceName} \"CoreGuard : protection temps réel, auto-défense, Mode Paranoïa, contrôle à distance.\"");
        }
        else
        {
            Run("sc.exe", $"config {ServiceName} binPath= \"\\\"{ServiceExe}\\\"\" start= auto");
        }
        Run("sc.exe", $"failure {ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/30000");
        Run("sc.exe", $"failureflag {ServiceName} 1");

        if (o.NewPassword is not null)
        {
            log("Enregistrement du mot de passe de protection (empreinte PBKDF2, jamais en clair)…");
            int code = Run(ServiceExe, "--set-password", stdin: o.NewPassword + "\n" + o.NewPassword + "\n");
            if (code != 0) throw new InvalidOperationException($"Mot de passe de protection non enregistré (code {code}).");
        }

        // Audit « Système de fichiers » (succès) : identification exacte du processus qui touche un leurre (4663)
        log("Activation de l'audit d'accès aux fichiers (leurres anti-ransomware et anti-infostealer)…");
        Run("auditpol.exe", "/set /subcategory:\"{0CCE921D-69AE-11D9-BED3-505054503030}\" /success:enable");
    }

    private void StartService()
    {
        log("Démarrage du service…");
        using var sc = new ServiceController(ServiceName);
        if (sc.Status != ServiceControllerStatus.Running) sc.Start();
        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));
        log("Service démarré (auto-défense : processus durci + watchdog).");
    }

    // ---------------------------------------------------------------- AMSI

    private void InstallAmsi()
    {
        string source = Path.Combine(payloadDir, "Amsi", "CoreGuard.AmsiProvider.dll");
        if (!File.Exists(source)) { log("Fournisseur AMSI absent de la charge utile : étape ignorée."); return; }
        log("Enregistrement du fournisseur AMSI (analyse des scripts avant exécution)…");
        string dir = Path.Combine(InstallDir, "Amsi");
        Directory.CreateDirectory(dir);
        string dll = Path.Combine(dir, "CoreGuard.AmsiProvider.dll");
        // La DLL est chargée par les PowerShell ouverts : on la renomme (autorisé) avant de copier la nouvelle
        if (File.Exists(dll)) File.Move(dll, Path.Combine(dir, $"CoreGuard.AmsiProvider.{DateTime.Now.Ticks}.old"));
        File.Copy(source, dll);
        foreach (string old in Directory.GetFiles(dir, "*.old")) TryDelete(old);

        using (var clsid = Registry.LocalMachine.CreateSubKey($@"SOFTWARE\Classes\CLSID\{AmsiClsid}"))
        {
            clsid.SetValue("", "CoreGuard AMSI Provider");
            using var inproc = clsid.CreateSubKey("InprocServer32");
            inproc.SetValue("", dll);
            inproc.SetValue("ThreadingModel", "Both");
        }
        using (var provider = Registry.LocalMachine.CreateSubKey($@"SOFTWARE\Microsoft\AMSI\Providers\{AmsiClsid}"))
            provider.SetValue("", "CoreGuard");
    }

    // ---------------------------------------------------------------- extension navigateur

    private void InstallBrowserHost()
    {
        log("Installation de l'hôte de l'extension (Chrome, Edge, Brave, Chromium)…");
        string dir = Path.Combine(InstallDir, "BrowserHost");
        CopyDirectory(Path.Combine(payloadDir, "BrowserHost"), dir);
        string manifest = Path.Combine(dir, NativeHostName + ".json");
        string exe = Path.Combine(dir, "CoreGuard.Extension.exe");
        File.WriteAllText(manifest, System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["name"] = NativeHostName,
            ["description"] = "Hôte Native Messaging CoreGuard (anti-phishing, coffre-fort)",
            ["path"] = exe,
            ["type"] = "stdio",
            ["allowed_origins"] = new[] { $"chrome-extension://{ExtensionId}/" }
        }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        // Pour tous les utilisateurs (HKLM) et pour l'utilisateur courant (HKCU, prioritaire sur HKLM pour Chrome)
        foreach (var root in new[] { Registry.LocalMachine, Registry.CurrentUser })
            foreach (string key in BrowserHostKeys)
            {
                using var k = root.CreateSubKey($@"{key}\{NativeHostName}");
                k.SetValue("", manifest);
            }
    }

    // ---------------------------------------------------------------- raccourcis, désinstallation

    private void CreateShortcuts(bool desktop)
    {
        log("Raccourcis du menu Démarrer…");
        string programs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "CoreGuard");
        Directory.CreateDirectory(programs);
        Shortcut(Path.Combine(programs, "CoreGuard.lnk"), AppExe, "", "Antivirus CoreGuard");
        string guide = Path.Combine(InstallDir, "Docs", "GUIDE.md");
        if (File.Exists(guide)) Shortcut(Path.Combine(programs, "Guide de CoreGuard.lnk"), "notepad.exe", $"\"{guide}\"", "Guide d'utilisation");
        Shortcut(Path.Combine(programs, "Désinstaller CoreGuard.lnk"), Path.Combine(InstallDir, "Setup", "CoreGuard-Setup.exe"), "--uninstall", "Désinstaller CoreGuard");
        if (desktop) Shortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "CoreGuard.lnk"), AppExe, "", "Antivirus CoreGuard");
    }

    private static void Shortcut(string lnk, string target, string args, string description)
    {
        Type shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("WScript.Shell indisponible.");
        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic link = shell.CreateShortcut(lnk);
        link.TargetPath = target;
        link.Arguments = args;
        link.Description = description;
        link.WorkingDirectory = Path.GetDirectoryName(target) ?? "";
        if (File.Exists(AppExe)) link.IconLocation = AppExe + ",0";
        link.Save();
    }

    private void CopySelf()
    {
        string dir = Path.Combine(InstallDir, "Setup");
        Directory.CreateDirectory(dir);
        string self = Environment.ProcessPath!;
        string target = Path.Combine(dir, "CoreGuard-Setup.exe");
        if (!string.Equals(Path.GetFullPath(self), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase)) File.Copy(self, target, overwrite: true);
    }

    private void RegisterUninstall()
    {
        using var k = Registry.LocalMachine.CreateSubKey(UninstallKey);
        k.SetValue("DisplayName", "CoreGuard — Antivirus");
        k.SetValue("Publisher", "Tchuente Krys");
        k.SetValue("DisplayVersion", "1.0.0");
        k.SetValue("DisplayIcon", AppExe);
        k.SetValue("InstallLocation", InstallDir);
        k.SetValue("UninstallString", $"\"{Path.Combine(InstallDir, "Setup", "CoreGuard-Setup.exe")}\" --uninstall");
        k.SetValue("NoModify", 1, RegistryValueKind.DWord);
        k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        k.SetValue("EstimatedSize", (int)(DirectorySize(InstallDir) / 1024), RegistryValueKind.DWord);
    }

    /// <summary>Désinstallation : le mot de passe de protection est exigé pour arrêter le service (auto-défense).</summary>
    public void Uninstall(string? currentPassword, bool removeUserData, IProgress<int> progress)
    {
        StopRunning(currentPassword);
        progress.Report(30);
        if (ServiceExists) { log("Suppression du service…"); Run("sc.exe", $"delete {ServiceName}"); }
        log("Retrait du fournisseur AMSI et de l'hôte de l'extension…");
        Registry.LocalMachine.DeleteSubKeyTree($@"SOFTWARE\Microsoft\AMSI\Providers\{AmsiClsid}", false);
        Registry.LocalMachine.DeleteSubKeyTree($@"SOFTWARE\Classes\CLSID\{AmsiClsid}", false);
        foreach (var root in new[] { Registry.LocalMachine, Registry.CurrentUser })
            foreach (string key in BrowserHostKeys) root.DeleteSubKeyTree($@"{key}\{NativeHostName}", false);
        using (var run = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true))
            run?.DeleteValue("CoreGuard", throwOnMissingValue: false);
        progress.Report(55);

        log("Suppression des fichiers et des raccourcis…");
        TryDeleteDirectory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "CoreGuard"));
        TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "CoreGuard.lnk"));
        foreach (string part in new[] { "App", "Service", "BrowserHost", "Extension", "Docs", "Demo", "Amsi" })
            TryDeleteDirectory(Path.Combine(InstallDir, part));
        Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, false);
        if (removeUserData)
        {
            log("Suppression des données (réglages, quarantaine, coffre, configuration du service)…");
            TryDeleteDirectory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CoreGuard"));
            TryDeleteDirectory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CoreGuard"));
        }
        progress.Report(100);
        log("Désinstallation terminée. Le dossier Setup sera retiré au prochain redémarrage.");
        Run("cmd.exe", $"/c ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{Path.Combine(InstallDir, "Setup")}\"", wait: false);
    }

    // ---------------------------------------------------------------- utilitaires

    private int Run(string file, string args, string? stdin = null, bool wait = true)
    {
        var psi = new ProcessStartInfo(file, args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = stdin is not null, RedirectStandardOutput = true, RedirectStandardError = true
        };
        using var p = Process.Start(psi)!;
        if (!wait) return 0;
        if (stdin is not null) { p.StandardInput.Write(stdin); p.StandardInput.Close(); }
        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(120_000);
        foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (!line.Contains("mot de passe", StringComparison.OrdinalIgnoreCase) || line.Length < 120) log("   " + line);
        return p.ExitCode;
    }

    private void CopyDirectory(string source, string target)
    {
        foreach (string dir in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(target, Path.GetRelativePath(source, dir)));
        Directory.CreateDirectory(target);
        foreach (string file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            string dest = Path.Combine(target, Path.GetRelativePath(source, file));
            var fi = new FileInfo(file);
            if (File.Exists(dest) && new FileInfo(dest).Length == fi.Length && File.GetLastWriteTimeUtc(dest) >= fi.LastWriteTimeUtc) continue;
            File.Copy(file, dest, overwrite: true);
        }
    }

    private static long DirectorySize(string dir) =>
        Directory.Exists(dir) ? new DirectoryInfo(dir).EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length) : 0;

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log($"   {path} : suppression partielle ({ex.Message})"); }
    }
}
