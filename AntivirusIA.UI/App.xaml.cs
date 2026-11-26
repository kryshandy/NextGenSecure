using System.Diagnostics;
using System.Windows;
using AntivirusIA.AI;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Services;
using AntivirusIA.Engines;
using AntivirusIA.Infrastructure;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Services;
using AntivirusIA.UI.ViewModels;
using CoreGuard.Network;
using CoreGuard.Response;
using Microsoft.Extensions.DependencyInjection;

namespace AntivirusIA.UI;

/// <summary>
/// Composition root : construit le conteneur d'injection, résout la MainWindow et démarre la protection.
/// Lancement : <c>dotnet run --project AntivirusIA.UI</c> depuis la racine du dépôt (le modèle IA
/// <c>models/Llama-3.2-3B-Instruct-Q4_K_M.gguf</c> est résolu depuis le répertoire courant).
/// </summary>
public partial class App : Application
{
    private ServiceProvider? _services;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += (_, args) =>
        {
            Trace.WriteLine($"[CoreGuard] Erreur non gérée : {args.Exception}");
            args.Handled = true; // une erreur d'affichage ne doit pas tuer la protection
        };

        string dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CoreGuard");
        Directory.CreateDirectory(dataDir);

        // Réglages chargés avant la construction des services (chemin du modèle IA, seuils...)
        var store = new SettingsStore(Path.Combine(dataDir, "settings.json"));
        var settings = store.Load();

        var services = new ServiceCollection();
        ConfigureServices(services, dataDir, store, settings);
        _services = services.BuildServiceProvider();

        _services.GetRequiredService<ThemeService>().Apply(settings.DarkTheme);

        var window = _services.GetRequiredService<MainWindow>();
        MainWindow = window;
        window.Show();

        // Démarre les modules temps réel hors thread UI ; les échecs sont isolés module par module
        _ = _services.GetRequiredService<ProtectionService>().ApplyAsync();
        // Lien avec le service SYSTEM : s'il répond, il reprend la télémétrie ETW (sinon fonctionnement autonome)
        _services.GetRequiredService<ServiceLink>().Start();
        _services.GetRequiredService<VaultService>().StartBroker();
        _ = _services.GetRequiredService<QuarantineViewModel>().OnNavigatedToAsync();
        _ = LoadStatsAsync(_services);
    }

    private static void ConfigureServices(IServiceCollection services, string dataDir, SettingsStore store, AppSettings settings)
    {
        // Réglages et services applicatifs
        services.AddSingleton(settings);
        services.AddSingleton(store);
        services.AddSingleton<ThemeService>();
        services.AddSingleton<IDialogService, DialogService>();
        services.AddSingleton<AlertHub>();
        services.AddSingleton<ActivityStats>();

        // Moteurs de détection (tous exposés comme IDetectionEngine, consommés par ScanPipeline)
        // Signatures : base livrée + bases additionnelles déposées par l'utilisateur (listes SHA-256 .txt/.json)
        string data = Path.Combine(AppContext.BaseDirectory, "Data");
        string userSignatures = Path.Combine(dataDir, "signatures");
        Directory.CreateDirectory(userSignatures);
        services.AddSingleton<IDetectionEngine>(_ => new SignatureEngine(
            [Path.Combine(data, "signatures.json"), Path.Combine(data, "signatures"), userSignatures]));
        services.AddSingleton<IDetectionEngine>(_ => new PatternRuleEngine(Path.Combine(data, "rules.json")));
        services.AddSingleton<IDetectionEngine, HeuristicEngine>();
        services.AddSingleton<IDetectionEngine, EntropyAnalyzer>();
        services.AddSingleton<IDetectionEngine, PeStaticEngine>();
        services.AddSingleton<IFileTrustProvider, AuthenticodeVerifier>();
        services.AddSingleton(new ScoringService
        {
            SeuilSuspect = settings.ThresholdSuspect,
            SeuilMalveillant = settings.ThresholdMalicious
        });
        services.AddSingleton<ScanPipeline>();

        // Infrastructure : quarantaine chiffrée et historique SQLite sous %LocalAppData%\CoreGuard
        services.AddSingleton<IQuarantineService>(sp => new QuarantineService(
            Path.Combine(dataDir, "quarantine"), sp.GetRequiredService<IKernelActionProvider>()));

        // Actions de réponse : mode utilisateur aujourd'hui ; le driver Ring 0 fournira une autre
        // implémentation de IKernelActionProvider, à substituer ici sans toucher aux modules
        services.AddSingleton<IKernelActionProvider>(sp =>
        {
            var firewall = sp.GetRequiredService<INetworkGuard>();
            return new UserModeActionProvider((rule, path) =>
            {
                if (!firewall.CanManageFirewall) return false;
                firewall.BlockApplication(rule, path);
                return true;
            });
        });
        services.AddSingleton<IScanRepository>(_ => new SqliteScanRepository(Path.Combine(dataDir, "coreguard.db")));

        // IA locale (LLamaSharp) : le modèle n'est chargé qu'au premier appel ; absent => repli sur le verdict local
        services.AddCoreGuardAi(new AiOptions { ModelPath = ModelLocator.Resolve(settings.ModelPath) });

        // Modules CoreGuard temps réel
        services.AddSingleton<INetworkGuard, WindowsFirewall>();
        services.AddSingleton<UiThreatResponder>();
        services.AddSingleton<ServiceLink>();
        // Gestionnaire de mots de passe (coffre local) + canal d'auto-remplissage pour l'extension
        services.AddSingleton(sp => new VaultService(dataDir, sp.GetRequiredService<AlertHub>()));
        services.AddSingleton<ProtectionService>();
        services.AddSingleton<ScanService>();

        // ViewModels et fenêtre
        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<ScanViewModel>();
        services.AddSingleton<QuarantineViewModel>();
        services.AddSingleton<HistoryViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<VaultViewModel>();
        services.AddSingleton<MainViewModel>();
        services.AddSingleton<MainWindow>();
    }

    // Initialise les compteurs du tableau de bord depuis l'historique persistant
    private static async Task LoadStatsAsync(IServiceProvider sp)
    {
        try
        {
            var history = await sp.GetRequiredService<IScanRepository>().GetHistoryAsync(5000);
            var stats = sp.GetRequiredService<ActivityStats>();
            stats.FilesScanned = history.Count;
            stats.ThreatsFound = history.Count(r => r.Verdict != AntivirusIA.Core.Models.Verdict.Sain);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Trace.WriteLine($"[CoreGuard] Historique illisible : {ex.Message}");
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Retire les canaris et arrête les moniteurs proprement
        _services?.Dispose();
        base.OnExit(e);
    }
}
