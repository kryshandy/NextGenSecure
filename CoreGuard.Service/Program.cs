using AntivirusIA.Core.Interfaces;
using CoreGuard.Network;
using CoreGuard.Response;
using CoreGuard.Service;

// Service Windows CoreGuard (compte LocalSystem, session 0).
// Installation : scripts/install-service.ps1 (administrateur). En développement, il peut aussi être lancé
// en console (`dotnet run --project CoreGuard.Service`) : il fonctionne alors avec les droits de l'utilisateur,
// et l'UI ne l'accepte que si la variable d'environnement COREGUARD_DEV_SERVICE=1 est définie (build Debug).
var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = ServiceIdentity.ServiceName);

builder.Services.AddSingleton<INetworkGuard, WindowsFirewall>();
builder.Services.AddSingleton<IKernelActionProvider>(sp =>
{
    var firewall = sp.GetRequiredService<INetworkGuard>();
    return new UserModeActionProvider((rule, path) =>
    {
        if (!firewall.CanManageFirewall) return false;
        firewall.BlockApplication(rule, path);
        return true;
    });
});
builder.Services.AddHostedService<ProtectionWorker>();

builder.Build().Run();
