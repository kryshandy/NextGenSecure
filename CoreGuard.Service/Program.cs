using System.Globalization;
using AntivirusIA.Core.Interfaces;
using CoreGuard.Ipc;
using CoreGuard.Network;
using CoreGuard.Response;
using CoreGuard.Service;

// Service Windows CoreGuard (compte LocalSystem, session 0).
//
//   (aucun argument)        hôte : service Windows, ou console en développement
//   --harden                (console) active aussi DACL durcie + watchdog — toujours actifs en service Windows
//   --supervise             (console, tests) watchdog seul, sans DACL durcie : relance testable par taskkill
//   --watchdog <pid>        mode watchdog (lancé par le service lui-même)
//   --set-password [--dev]  définit le mot de passe de protection (administrateur hors --dev)
//   --stop [--dev]          demande l'arrêt authentifié du service en cours d'exécution
//
// Installation : scripts/install-service.ps1 (administrateur). En développement, l'UI n'accepte un service
// lancé en console que si elle est compilée en Debug et lancée avec COREGUARD_DEV_SERVICE=1.
var argList = args.ToList();
ServiceHost.DevMode = argList.Contains("--dev");

if (argList.Contains("--set-password")) return ServiceCli.SetPassword();
if (argList.Contains("--stop")) return await ServiceCli.StopAsync();

int watchdogIndex = argList.IndexOf("--watchdog");
if (watchdogIndex >= 0)
{
    ServiceHost.IsConsoleRun = argList.Contains("--console");
    ServiceHost.DevMode = ServiceHost.IsConsoleRun;
    if (watchdogIndex + 1 >= argList.Count || !int.TryParse(argList[watchdogIndex + 1], NumberStyles.None, CultureInfo.InvariantCulture, out int pid))
        return 2;
    return await WatchdogRunner.RunAsync(pid, argList.Contains("--harden"), ServiceHost.IsConsoleRun);
}

ServiceHost.IsConsoleRun = !ServiceHost.IsWindowsService;
ServiceHost.DevMode |= ServiceHost.IsConsoleRun;
bool harden = ServiceHost.IsWindowsService || argList.Contains("--harden");
bool supervise = harden || argList.Contains("--supervise");

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = ServiceIdentity.ServiceName);
if (ServiceHost.IsWindowsService && OperatingSystem.IsWindows())
    builder.Services.AddSingleton<IHostLifetime, ProtectedServiceLifetime>(); // refuse sc stop / Stop-Service

builder.Services.AddSingleton(new ServiceOptions(harden, supervise));
builder.Services.AddSingleton(_ => new StopAuthenticator(ProtectionSecret.Load(ServiceHost.SecretPath)));
builder.Services.AddSingleton<WatchdogSupervisor>();
builder.Services.AddSingleton<INetworkGuard, WindowsFirewall>();
builder.Services.AddSingleton<UserModeActionProvider>(sp =>
{
    var firewall = sp.GetRequiredService<INetworkGuard>();
    return new UserModeActionProvider((rule, path) =>
    {
        if (!firewall.CanManageFirewall) return false;
        firewall.BlockApplication(rule, path);
        return true;
    });
});
builder.Services.AddSingleton<IKernelActionProvider>(sp => sp.GetRequiredService<UserModeActionProvider>());
builder.Services.AddHostedService<ProtectionWorker>();

await builder.Build().RunAsync();
return 0;
