using System.Diagnostics;
using CoreGuard.Ipc;

namespace CoreGuard.Ipc.Tests;

[TestClass]
public sealed class VaultBrokerTests
{
    private static string NewPipe() => "CoreGuard.Test.Vault." + Guid.NewGuid().ToString("N");

    [TestMethod]
    [DataRow("https://www.banque.fr", "www.banque.fr", true)]
    [DataRow("https://banque.fr", "www.banque.fr", true)]
    [DataRow("banque.fr", "connexion.banque.fr", true)]
    [DataRow("https://www.banque.fr", "banque.fr", false)]
    [DataRow("https://banque.fr", "banque.fr.evil.net", false)]
    [DataRow("https://banque.fr", "monbanque.fr", false)]
    [DataRow("", "banque.fr", false)]
    public void Correspondance_identifiant_page(string entry, string page, bool expected)
    {
        Assert.AreEqual(expected, VaultBroker.MatchesHost(entry, page));
    }

    [TestMethod]
    public async Task Un_client_autorise_recoit_l_identifiant()
    {
        string pipe = NewPipe();
        using var cts = new CancellationTokenSource();
        int? seenPid = null;
        _ = VaultBroker.ServeAsync(
            url => Task.FromResult(url.StartsWith("https://site.test") ? new CredentialLookup(true, "bob", "pw", false) : CredentialLookup.NotFound),
            pid => { seenPid = pid; return true; }, cts.Token, pipe);

        var result = await VaultBroker.FindAsync("https://site.test/login", default, pipe);
        cts.Cancel();

        Assert.IsTrue(result.Found);
        Assert.AreEqual("bob", result.Username);
        Assert.AreEqual(Environment.ProcessId, seenPid, "le serveur identifie le processus client");
    }

    [TestMethod]
    public async Task Un_client_non_autorise_est_refuse_sans_consulter_le_coffre()
    {
        string pipe = NewPipe();
        using var cts = new CancellationTokenSource();
        bool looked = false;
        _ = VaultBroker.ServeAsync(_ => { looked = true; return Task.FromResult(new CredentialLookup(true, "bob", "pw", false)); },
            _ => false, cts.Token, pipe);

        var result = await VaultBroker.FindAsync("https://site.test/", default, pipe);
        cts.Cancel();

        Assert.IsFalse(result.Found);
        Assert.IsTrue(result.Denied);
        Assert.IsFalse(looked);
        Assert.IsNull(result.Password);
    }

    [TestMethod]
    public async Task Sans_interface_le_coffre_est_vu_comme_verrouille()
    {
        var result = await VaultBroker.FindAsync("https://site.test/", default, NewPipe());
        Assert.IsTrue(result.Locked);
        Assert.IsFalse(result.Found);
    }

    [TestMethod]
    public void L_ascendance_d_un_processus_enfant_contient_son_parent()
    {
        using var child = Process.Start(new ProcessStartInfo("ping.exe", "-n 10 127.0.0.1") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!;
        try
        {
            CollectionAssert.Contains(ProcessAncestry.Ancestors(child.Id).ToList(), Environment.ProcessId);
            StringAssert.EndsWith(ProcessAncestry.ImagePath(child.Id)!, "PING.EXE", StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            child.Kill();
        }
    }
}
