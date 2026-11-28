using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoreGuard.Service.Tests;

/// <summary>Contrôle à distance par téléphone : authentification des ordres et serveur HTTP réel.</summary>
[TestClass]
public sealed class RemoteControlTests
{
    private static readonly byte[] Key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

    [TestMethod]
    public void Ordre_signe_accepte_une_seule_fois()
    {
        var auth = new RemoteControlAuth(Key);
        string c = auth.IssueChallenge();
        Assert.IsTrue(auth.Verify(c, "lock", RemoteControlAuth.Sign(Key, c, "lock")).Ok);
        Assert.IsFalse(auth.Verify(c, "lock", RemoteControlAuth.Sign(Key, c, "lock")).Ok, "rejeu refusé");
    }

    [TestMethod]
    public void Mauvaise_cle_action_modifiee_ou_defi_expire_refuses()
    {
        var now = new DateTime(2026, 11, 28, 10, 0, 0, DateTimeKind.Utc);
        var auth = new RemoteControlAuth(Key, () => now);
        string c1 = auth.IssueChallenge();
        Assert.IsFalse(auth.Verify(c1, "unlock", RemoteControlAuth.Sign(new byte[32], c1, "unlock")).Ok, "autre clé");
        string c2 = auth.IssueChallenge();
        Assert.IsFalse(auth.Verify(c2, "unlock", RemoteControlAuth.Sign(Key, c2, "lock")).Ok, "signature d'une autre action");
        string c3 = auth.IssueChallenge();
        now += TimeSpan.FromSeconds(61);
        Assert.IsFalse(auth.Verify(c3, "lock", RemoteControlAuth.Sign(Key, c3, "lock")).Ok, "défi expiré");
        Assert.IsFalse(auth.Verify("inconnu", "format", new string('0', 64)).Ok, "action hors liste");
    }

    [TestMethod]
    public void Cinq_echecs_bloquent_cinq_minutes()
    {
        var now = new DateTime(2026, 11, 28, 10, 0, 0, DateTimeKind.Utc);
        var auth = new RemoteControlAuth(Key, () => now);
        for (int i = 0; i < RemoteControlAuth.MaxFailures; i++) auth.Verify(auth.IssueChallenge(), "lock", new string('0', 64));
        string c = auth.IssueChallenge();
        Assert.IsFalse(auth.Verify(c, "lock", RemoteControlAuth.Sign(Key, c, "lock")).Ok, "même un bon ordre est refusé pendant le blocage");
        now += RemoteControlAuth.Lockout + TimeSpan.FromSeconds(1);
        c = auth.IssueChallenge();
        Assert.IsTrue(auth.Verify(c, "lock", RemoteControlAuth.Sign(Key, c, "lock")).Ok);
    }

    [TestMethod]
    public async Task Serveur_reel_page_defi_et_ordre_signe_execute()
    {
        int port = FreePort();
        var config = new RemoteControlConfig(true, port, RemoteControlConfig.Base64Url(Key), DateTime.UtcNow);
        var executed = new List<string>();
        var published = new List<string>();
        using var server = new RemoteControlServer(config, a => { lock (executed) executed.Add(a); return (true, "fait"); },
            () => new { lockdown = executed.Contains("lock"), paranoia = false },
            (_, _, title, _) => { lock (published) published.Add(title); }, NullLogger.Instance);
        server.Start();
        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}") };

        string page = await http.GetStringAsync("/");
        StringAssert.Contains(page, "hmacSha256");

        async Task<JsonElement> Command(string action, Func<string, string> mac)
        {
            using var c = JsonDocument.Parse(await (await http.PostAsync("/api/challenge", null)).Content.ReadAsStringAsync());
            string challenge = c.RootElement.GetProperty("challenge").GetString()!;
            var body = new StringContent(JsonSerializer.Serialize(new { challenge, action, mac = mac(challenge) }), Encoding.UTF8, "application/json");
            return JsonDocument.Parse(await (await http.PostAsync("/api/command", body)).Content.ReadAsStringAsync()).RootElement.Clone();
        }

        var ok = await Command("lock", ch => RemoteControlAuth.Sign(Key, ch, "lock"));
        Assert.IsTrue(ok.GetProperty("ok").GetBoolean());
        Assert.IsTrue(ok.GetProperty("status").GetProperty("lockdown").GetBoolean());
        var bad = await Command("unlock", ch => RemoteControlAuth.Sign(new byte[32], ch, "unlock"));
        Assert.IsFalse(bad.GetProperty("ok").GetBoolean(), "téléphone non associé refusé");
        CollectionAssert.AreEqual(new[] { "lock" }, executed);
        Assert.IsTrue(published.Contains("Ordre refusé"));
    }

    [TestMethod]
    public void Urls_contiennent_la_cle_dans_le_fragment()
    {
        var config = RemoteControlConfig.CreateNew(8742);
        Assert.AreEqual(32, config.KeyBytes.Length);
        foreach (string url in config.Urls()) StringAssert.EndsWith(url, "/#k=" + config.Key);
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
