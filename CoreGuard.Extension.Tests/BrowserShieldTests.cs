using System.Text.Json;
using CoreGuard.Extension;
using CoreGuard.Ipc;

namespace CoreGuard.Extension.Tests;

[TestClass]
public sealed class BrowserShieldTests
{
    // ---------- Vérification à la navigation ----------

    [TestMethod]
    public void Un_site_legitime_est_sur()
    {
        Assert.AreEqual(PhishingVerdict.Safe, PhishingLogic.AssessNavigation("https://accounts.google.com/signin", true).Verdict);
    }

    [TestMethod]
    public void Une_marque_en_sous_domaine_d_un_domaine_tiers_est_du_phishing()
    {
        var r = PhishingLogic.AssessNavigation("https://paypal.com.connexion-securisee.net/login", false);
        Assert.AreEqual(PhishingVerdict.Phishing, r.Verdict);
        Assert.IsTrue(r.Reasons.Any(x => x.Contains("sous-domaine")));
    }

    [TestMethod]
    public void Une_adresse_IP_avec_mot_de_passe_est_du_phishing()
    {
        Assert.AreEqual(PhishingVerdict.Phishing, PhishingLogic.AssessNavigation("http://185.12.44.7/banque/login", true).Verdict);
        Assert.AreEqual(PhishingVerdict.Suspicious, PhishingLogic.AssessNavigation("https://185.12.44.7/", false).Verdict);
    }

    [TestMethod]
    public void Un_mot_de_passe_sur_http_est_suspect_mais_pas_en_local()
    {
        Assert.AreEqual(PhishingVerdict.Suspicious, PhishingLogic.AssessNavigation("http://forum-exemple.org/login", true).Verdict);
        Assert.AreEqual(PhishingVerdict.Safe, PhishingLogic.AssessNavigation("http://localhost:8080/login", true).Verdict);
    }

    [TestMethod]
    public void Le_typosquatting_reste_detecte()
    {
        Assert.AreEqual(PhishingVerdict.Phishing, PhishingLogic.AssessNavigation("https://paypa1.com/", false).Verdict);
    }

    // ---------- Hôte : commandes checkUrl et requestCredential ----------

    private sealed class FakeProvider(CredentialLookup answer) : ICredentialProvider
    {
        public List<string> Asked { get; } = [];
        public Task<CredentialLookup> FindAsync(string url, CancellationToken ct = default) { Asked.Add(url); return Task.FromResult(answer); }
    }

    private static async Task<JsonElement> Send(HostRouter router, object message)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(message));
        object reply = await router.HandleAsync(doc.RootElement);
        return JsonDocument.Parse(JsonSerializer.Serialize(reply)).RootElement;
    }

    [TestMethod]
    public async Task L_hote_repond_a_checkUrl()
    {
        var router = new HostRouter(new OcrPhishingAnalyzer(), new NullCredentialProvider());
        var reply = await Send(router, new { type = "checkUrl", url = "https://paypal.com.connexion-securisee.net/", hasPassword = true });
        Assert.AreEqual("Phishing", reply.GetProperty("verdict").GetString());
    }

    [TestMethod]
    public async Task L_hote_fournit_l_identifiant_d_une_page_https_legitime()
    {
        var provider = new FakeProvider(new CredentialLookup(true, "alice", "S3cret!", false));
        var reply = await Send(new HostRouter(new OcrPhishingAnalyzer(), provider), new { type = "requestCredential", url = "https://www.banque-exemple.fr/connexion" });
        Assert.IsTrue(reply.GetProperty("found").GetBoolean());
        Assert.AreEqual("alice", reply.GetProperty("username").GetString());
    }

    [TestMethod]
    public async Task L_hote_refuse_une_page_http_ou_typosquattee_sans_interroger_le_coffre()
    {
        var provider = new FakeProvider(new CredentialLookup(true, "alice", "S3cret!", false));
        var router = new HostRouter(new OcrPhishingAnalyzer(), provider);

        var http = await Send(router, new { type = "requestCredential", url = "http://www.banque-exemple.fr/connexion" });
        var typo = await Send(router, new { type = "requestCredential", url = "https://paypa1.com/login" });

        Assert.IsTrue(http.GetProperty("blocked").GetBoolean());
        Assert.IsTrue(typo.GetProperty("blocked").GetBoolean());
        Assert.AreEqual(0, provider.Asked.Count, "le coffre ne doit jamais être interrogé pour ces pages");
    }

    [TestMethod]
    public async Task L_hote_signale_un_coffre_verrouille()
    {
        var reply = await Send(new HostRouter(new OcrPhishingAnalyzer(), new FakeProvider(CredentialLookup.VaultLocked)),
            new { type = "requestCredential", url = "https://site.exemple.org/" });
        Assert.IsFalse(reply.GetProperty("found").GetBoolean());
        Assert.IsTrue(reply.GetProperty("locked").GetBoolean());
    }
}
