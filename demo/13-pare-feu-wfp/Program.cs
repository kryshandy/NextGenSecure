// DÉMO — INOFFENSIF : spécimen 13 (pare-feu natif WFP de CoreGuard)
// À lancer dans une console ADMINISTRATEUR : dotnet run --project demo/13-pare-feu-wfp
// 1. curl.exe joint un site : OK ;
// 2. CoreGuard pose un filtre WFP par AppId (FwpmFilterAdd0) sur curl.exe : la même requête échoue ;
// 3. la session WFP dynamique est fermée : Windows retire le filtre, curl fonctionne de nouveau.
// Rien n'est laissé sur la machine (session dynamique). Option : --bouclier ajoute le refus des connexions entrantes.
using System.Diagnostics;
using System.Security.Principal;
using CoreGuard.Network;

if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
{
    Console.WriteLine("Cette démonstration doit être lancée depuis une console ADMINISTRATEUR (WFP l'exige).");
    return 1;
}

string curl = Path.Combine(Environment.SystemDirectory, "curl.exe");
string url = args.FirstOrDefault(a => a.StartsWith("http", StringComparison.OrdinalIgnoreCase)) ?? "https://www.microsoft.com";

Console.WriteLine($"1) Sans filtre : curl {url}");
Report(Curl(url));

using (var wfp = new WfpFirewall(dynamic: true))
{
    var ids = wfp.BlockApplicationOutbound(curl, "Démo : curl.exe");
    Console.WriteLine($"\n2) Filtres WFP posés par AppId sur curl.exe : {string.Join(", ", ids)}");
    if (args.Contains("--bouclier"))
    {
        var shield = wfp.BlockAllInbound("Démo : bouclier");
        Console.WriteLine($"   Bouclier : connexions entrantes refusées (hors trafic local), filtres {string.Join(", ", shield)}");
    }
    Report(Curl(url));
    Console.WriteLine("   (vérification possible pendant ce temps : netsh wfp show filters, rechercher « CoreGuard »)");
    if (args.Contains("--auto")) Thread.Sleep(3000);
    else
    {
        Console.WriteLine("\nAppuyez sur Entrée pour fermer la session WFP...");
        Console.ReadLine();
    }
}

Console.WriteLine("3) Session fermée : filtres retirés par Windows.");
Report(Curl(url));
return 0;

static int Curl(string url)
{
    using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "curl.exe"), $"-s -o NUL -m 8 -w \"%{{http_code}}\" {url}")
    { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true })!;
    string code = p.StandardOutput.ReadToEnd();
    p.WaitForExit(15_000);
    Console.WriteLine($"   curl : code de sortie {p.ExitCode}, réponse HTTP {code}");
    return p.ExitCode;
}

static void Report(int exit) =>
    Console.WriteLine(exit == 0 ? "   => connexion RÉUSSIE" : "   => connexion BLOQUÉE");
