using CoreGuard.Extension;

namespace CoreGuard.Extension.Tests;

[TestClass]
public class PhishingLogicTests
{
    // ------------------------------------------------ Levenshtein

    [TestMethod]
    [DataRow("", "", 0)]
    [DataRow("abc", "", 3)]
    [DataRow("", "abc", 3)]
    [DataRow("kitten", "sitting", 3)]
    [DataRow("google", "google", 0)]
    [DataRow("google", "gooogle", 1)]
    [DataRow("paypal", "paypa1", 1)]
    public void Levenshtein_ValeursConnues(string a, string b, int attendu)
    {
        Assert.AreEqual(attendu, PhishingLogic.Levenshtein(a, b));
        Assert.AreEqual(attendu, PhishingLogic.Levenshtein(b, a)); // symétrie
    }

    // ------------------------------------------------ Homographes

    [TestMethod]
    public void Homographes_CyrilliqueMelangeAuLatin_EstSuspect()
    {
        // 'а' (U+0430) cyrillique à la place du 'a' latin.
        var r = PhishingLogic.DetectHomographs("pаypal.com");
        Assert.IsTrue(r.IsSuspicious);
        Assert.IsTrue(r.MixedScripts);
        CollectionAssert.Contains(r.Characters.ToList(), 'а');
    }

    [TestMethod]
    public void Homographes_GrecDeguise_EstSuspect()
    {
        // 'ο' grec (U+03BF) à la place du 'o' latin.
        Assert.IsTrue(PhishingLogic.DetectHomographs("gοogle.com").IsSuspicious);
    }

    [TestMethod]
    public void Homographes_LatinPur_NonSuspect() =>
        Assert.IsFalse(PhishingLogic.DetectHomographs("google.com").IsSuspicious);

    [TestMethod]
    public void Homographes_TexteRusseLegitime_NonSuspect() =>
        // Mot 100 % cyrillique avec lettres non confusables : pas un déguisement.
        Assert.IsFalse(PhishingLogic.DetectHomographs("привет.рф").IsSuspicious);

    [TestMethod]
    public void Skeleton_RamenerAuLatin() =>
        Assert.AreEqual("paypal", PhishingLogic.ToSkeleton("pаypаl"));

    // ------------------------------------------------ Domaines / typosquatting

    [TestMethod]
    [DataRow("https://accounts.google.com/signin", "google.com")]
    [DataRow("https://login.example.co.uk/x", "example.co.uk")]
    public void DomaineEnregistrable(string url, string attendu) =>
        Assert.AreEqual(attendu, PhishingLogic.GetRegistrableDomain(PhishingLogic.ExtractHost(url)!));

    [TestMethod]
    [DataRow("javascript:alert(1)")]
    [DataRow("file:///c:/x")]
    [DataRow("pas une url")]
    [DataRow(null)]
    public void ExtractHost_RejetteSchemasNonWeb(string? url) =>
        Assert.IsNull(PhishingLogic.ExtractHost(url));

    [TestMethod]
    [DataRow("gooogle.com", "google")]
    [DataRow("paypa1.com", "paypal")]
    [DataRow("micros0ft.com", "microsoft")]
    [DataRow("paypal-secure.com", "paypal")]
    public void Typosquatting_Detecte(string domaine, string marque) =>
        Assert.AreEqual(marque, PhishingLogic.DetectTyposquatting(domaine));

    [TestMethod]
    [DataRow("google.com")]
    [DataRow("microsoftonline.com")]
    [DataRow("wikipedia.org")]
    [DataRow("amazon.fr")]
    public void Typosquatting_DomainesLegitimesOuSansRapport(string domaine) =>
        Assert.IsNull(PhishingLogic.DetectTyposquatting(domaine));

    // ------------------------------------------------ Corrélation marque / domaine

    [TestMethod]
    public void Correlation_MarqueSurDomaineLegitime_Sure()
    {
        var r = PhishingLogic.Assess("Sign in to your Google account. Password", "https://accounts.google.com/");
        Assert.AreEqual(PhishingVerdict.Safe, r.Verdict);
    }

    [TestMethod]
    public void Correlation_MarqueSurDomaineTiersAvecConnexion_Phishing()
    {
        var r = PhishingLogic.Assess("Microsoft - Sign in. Enter your password", "https://secure-login.example.net/");
        Assert.AreEqual(PhishingVerdict.Phishing, r.Verdict);
        Assert.IsTrue(r.Reasons.Any(x => x.Contains("microsoft")));
    }

    [TestMethod]
    public void Correlation_MarqueSansConnexion_Suspect()
    {
        var r = PhishingLogic.Assess("Article : l'histoire de Google", "https://blog.example.org/");
        Assert.AreEqual(PhishingVerdict.Suspicious, r.Verdict);
    }

    [TestMethod]
    public void Correlation_BanqueFrancaiseAvecAccents_Phishing()
    {
        var r = PhishingLogic.Assess("Société Générale - Connexion à votre espace. Mot de passe", "https://sg-espace.example.com/");
        Assert.AreEqual(PhishingVerdict.Phishing, r.Verdict);
    }

    [TestMethod]
    public void Correlation_DomaineHomographe_Phishing()
    {
        var r = PhishingLogic.Assess("Sign in", "https://xn--pypal-4ve.com/");
        Assert.AreEqual(PhishingVerdict.Phishing, r.Verdict);
    }

    [TestMethod]
    public void Correlation_Typosquatting_PhishingMemeSansTexte()
    {
        var r = PhishingLogic.AssessUrl("https://paypa1.com/login");
        Assert.AreEqual(PhishingVerdict.Phishing, r.Verdict);
    }

    [TestMethod]
    public void Correlation_TexteSansMarqueSurSiteBanal_Sur() =>
        Assert.AreEqual(PhishingVerdict.Safe, PhishingLogic.Assess("Bienvenue. Mot de passe", "https://mon-club.example.org/").Verdict);

    [TestMethod]
    public void Correlation_UrlNonWeb_Sure() =>
        Assert.AreEqual(PhishingVerdict.Safe, PhishingLogic.Assess("Google", "chrome://settings").Verdict);

    // ------------------------------------------------ QR

    [TestMethod]
    [DataRow("https://evil.example/x", "https://evil.example/x")]
    [DataRow("javascript:alert(1)", null)]
    [DataRow("WIFI:S:x;;", null)]
    [DataRow("", null)]
    public void Qr_NormalizeUrl_NeGardeQueHttp(string contenu, string? attendu) =>
        Assert.AreEqual(attendu, QrCodeScanner.NormalizeUrl(contenu));
}
