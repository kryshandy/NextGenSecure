using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Principal;

namespace CoreGuard.Network.Tests;

/// <summary>Moteur WFP réel. Sans droits administrateur, seules les vérifications en lecture sont faites.</summary>
[TestClass]
public sealed class WfpFirewallTests
{
    private static bool Elevated => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    private static WfpFirewall? TryOpen()
    {
        try { return new WfpFirewall(dynamic: true); }
        catch (NetworkGuardException ex) when (!Elevated)
        {
            Assert.Inconclusive("WFP exige les droits administrateur : " + ex.Message);
            return null;
        }
    }

    private const uint LayerNotFound = 0x80320004; // FWP_E_LAYER_NOT_FOUND

    [TestMethod]
    public void Couches_utilisees_existent_dans_le_moteur()
    {
        // Sans droits administrateur, une couche existante répond « accès refusé » (5) et une couche inconnue
        // « introuvable » : les identifiants utilisés par CoreGuard sont vérifiés sur le vrai moteur dans les deux cas.
        using var wfp = TryOpen()!;
        foreach (var layer in new[] { WfpFirewall.LayerConnectV4, WfpFirewall.LayerConnectV6, WfpFirewall.LayerRecvAcceptV4, WfpFirewall.LayerRecvAcceptV6 })
            Assert.AreNotEqual(LayerNotFound, wfp.LayerStatus(layer), layer.ToString());
        Assert.AreEqual(LayerNotFound, wfp.LayerStatus(Guid.NewGuid()));
    }

    [TestMethod]
    public void Blocage_sortant_par_AppId_reel_puis_leve_a_la_fermeture()
    {
        if (!Elevated) Assert.Inconclusive("Test de blocage réel : console administrateur requise.");
        // Serveur HTTP local qui répond 200 : curl réussit (code 0) sauf si WFP lui interdit de se connecter
        int port = FreePort();
        using var http = new System.Net.HttpListener();
        http.Prefixes.Add($"http://127.0.0.1:{port}/");
        http.Start();
        _ = Task.Run(async () =>
        {
            while (http.IsListening)
            {
                try { var ctx = await http.GetContextAsync(); ctx.Response.StatusCode = 200; ctx.Response.Close(); }
                catch (Exception) { return; }
            }
        });
        string url = $"http://127.0.0.1:{port}/";
        Assert.AreEqual(0, RunCurl(url), "sans filtre : curl joint le serveur local");

        string curl = Path.Combine(Environment.SystemDirectory, "curl.exe");
        using (var wfp = new WfpFirewall(dynamic: true))
        {
            var ids = wfp.BlockApplicationOutbound(curl, "test curl");
            Assert.HasCount(2, ids);
            Assert.AreNotEqual(0, RunCurl(url), "filtre WFP par AppId : connexion refusée");
        }
        Assert.AreEqual(0, RunCurl(url), "session dynamique fermée : Windows a retiré le filtre");
    }

    private static int FreePort()
    {
        var l = new TcpListener(System.Net.IPAddress.Loopback, 0);
        l.Start();
        int port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static int RunCurl(string url)
    {
        using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "curl.exe"), $"-s -o NUL -m 5 {url}")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true })!;
        p.WaitForExit(10_000);
        return p.ExitCode;
    }
}
