using CoreGuard.Extension;

namespace CoreGuard.Extension.Tests;

/// <summary>Base de confiance réelle (Tranco 100 000, Public Suffix List, OpenPhish) et cascade de décision.</summary>
[TestClass]
public class TrustCascadeTests
{
    private static TrustBase _real = null!;

    [ClassInitialize]
    public static void Load(TestContext _)
    {
        string data = Path.Combine(AppContext.BaseDirectory, "Data");
        _real = new TrustBase(PublicSuffixList.Load(Path.Combine(data, "public_suffix_list.dat")),
            File.ReadLines(Path.Combine(data, "top-domains.txt")),
            ["https://paypa1-secure-login.example/connexion", "https://docs.google.com/forms/d/e/PIEGE/viewform", "https://faux-colis.vercel.app/"],
            ["site-de-confiance.example"]);
    }

    private static SiteAnalyzer Analyzer() => new(_real);

    [TestMethod]
    public void Base_chargee_avec_les_vraies_listes()
    {
        Assert.AreEqual(100_000, _real.KnownCount);
        Assert.IsGreaterThan(5_000, _real.Suffixes.Count);
    }

    [TestMethod]
    [DataRow("www.impots.gouv.fr", "impots.gouv.fr")]
    [DataRow("secure.paypal.co.uk", "paypal.co.uk")]
    [DataRow("faux-colis.vercel.app", "faux-colis.vercel.app")]
    [DataRow("a.b.github.io", "b.github.io")]
    [DataRow("www.google.com", "google.com")]
    [DataRow("localhost", "localhost")]
    public void Domaine_enregistrable_selon_la_PSL(string host, string attendu) =>
        Assert.AreEqual(attendu, _real.RegistrableDomain(host));

    [TestMethod]
    public void Hebergeurs_partages_reconnus()
    {
        Assert.IsTrue(_real.IsContentHost("faux-colis.vercel.app"));
        Assert.IsTrue(_real.IsContentHost("sites.google.com"));
        Assert.IsFalse(_real.IsContentHost("www.google.com"));
    }

    [TestMethod]
    public void Site_connu_sur_sans_capture()
    {
        var d = Analyzer().CheckNavigation("https://www.wikipedia.org/", hasPassword: true);
        Assert.AreEqual(PhishingVerdict.Safe, d.Verdict);
        Assert.AreEqual(SiteTrust.Known, d.Trust);
        Assert.IsFalse(d.NeedsCapture);
    }

    [TestMethod]
    public void Liste_noire_bloque_un_hote_dedie_entier()
    {
        var d = Analyzer().CheckNavigation("https://paypa1-secure-login.example/autre-page", false);
        Assert.AreEqual(PhishingVerdict.Phishing, d.Verdict);
        Assert.AreEqual(SiteTrust.Blocklisted, d.Trust);
        Assert.AreEqual(PhishingVerdict.Phishing, Analyzer().CheckNavigation("https://faux-colis.vercel.app/suivi", false).Verdict);
    }

    [TestMethod]
    public void Liste_noire_sur_service_connu_ne_bloque_que_l_adresse()
    {
        Assert.AreEqual(SiteTrust.Blocklisted, Analyzer().CheckNavigation("https://docs.google.com/forms/d/e/PIEGE/viewform", false).Trust);
        Assert.AreNotEqual(SiteTrust.Blocklisted, Analyzer().CheckNavigation("https://docs.google.com/forms/d/e/AUTRE/viewform", false).Trust);
    }

    [TestMethod]
    public void Confiance_utilisateur_l_emporte()
    {
        var d = Analyzer().CheckNavigation("https://site-de-confiance.example/login", true);
        Assert.AreEqual(PhishingVerdict.Safe, d.Verdict);
        Assert.AreEqual(SiteTrust.UserTrusted, d.Trust);
    }

    [TestMethod]
    public void Mot_de_passe_sur_hebergeur_gratuit_suspect()
    {
        var d = Analyzer().CheckNavigation("https://ma-page.netlify.app/login", true);
        Assert.AreEqual(PhishingVerdict.Suspicious, d.Verdict);
        Assert.AreEqual(SiteTrust.ContentHost, d.Trust);
        Assert.IsTrue(d.NeedsCapture);
    }

    [TestMethod]
    public void Domaine_inconnu_avec_connexion_demande_capture()
    {
        var d = Analyzer().CheckNavigation("https://boutique-artisanale-xyz.example/compte", true);
        Assert.AreEqual(SiteTrust.Unknown, d.Trust);
        Assert.IsTrue(d.NeedsCapture);
    }

    [TestMethod]
    public void Marque_affichee_sur_domaine_inconnu_phishing_et_revue()
    {
        var d = Analyzer().CheckPage("https://verification-compte-client.example/login",
            "PayPal\nConnectez-vous à votre compte\nAdresse e-mail\nMot de passe\nConnexion", hasPassword: true);
        Assert.AreEqual(PhishingVerdict.Phishing, d.Verdict);
        CollectionAssert.Contains(d.Brands.ToList(), "paypal");
        Assert.IsTrue(d.NeedsReview);
    }

    [TestMethod]
    public void Page_de_connexion_sans_marque_pas_soumise_a_l_IA()
    {
        var d = Analyzer().CheckPage("https://club-de-tennis-xyz.example/membres", "Espace membres\nIdentifiant\nMot de passe", true);
        Assert.AreEqual(PhishingVerdict.Safe, d.Verdict);
        Assert.IsFalse(d.NeedsReview, "un simple identifiant / mot de passe ne justifie pas d'aggraver");
    }

    [TestMethod]
    public void Donnees_sensibles_sans_marque_zone_grise_pour_l_IA()
    {
        var d = Analyzer().CheckPage("https://suivi-colis-xyz.example/frais",
            "Votre colis est bloqué. Frais de 1,99 €. Numéro de carte bancaire. Cryptogramme (CVV). Payer", true);
        Assert.AreEqual(PhishingVerdict.Safe, d.Verdict);   // aucune règle ne se déclenche…
        Assert.IsTrue(d.NeedsReview);                       // …mais la demande de carte justifie la revue par l'IA
    }

    [TestMethod]
    public void Marque_sur_son_propre_domaine_marque_propre()
    {
        var d = Analyzer().CheckPage("https://www.orange.cm/fr/orange-money.html", "Orange Money\nCode secret\nValider", true);
        Assert.AreEqual(PhishingVerdict.Safe, d.Verdict);
        CollectionAssert.Contains((d.OwnBrands ?? []).ToList(), "orange");
        Assert.IsFalse(d.NeedsReview);
    }

    [TestMethod]
    public void Site_connu_qui_cite_une_marque_reste_sur()
    {
        var d = Analyzer().CheckPage("https://www.lemonde.fr/economie", "PayPal annonce ses résultats. Se connecter", true);
        Assert.AreEqual(PhishingVerdict.Safe, d.Verdict);
        Assert.IsFalse(d.NeedsReview);
    }

    [TestMethod]
    [DataRow("pineapple-shop.example")]
    [DataRow("orangerie-paris.example")]
    [DataRow("amelie-boutique.example")]
    [DataRow("imports-auto.example")]
    public void Mots_courants_ne_sont_pas_du_typosquatting(string domaine) =>
        Assert.IsNull(PhishingLogic.DetectTyposquatting(domaine));

    [TestMethod]
    [DataRow("paypa1.example", "paypal")]
    [DataRow("netfiix.example", "netflix")]
    [DataRow("ameli-remboursement.example", "ameli")]
    [DataRow("impots-remboursement.example", "impots")]
    public void Typosquatting_des_marques_retenues(string domaine, string marque) =>
        Assert.AreEqual(marque, PhishingLogic.DetectTyposquatting(domaine));

    [TestMethod]
    public void Excerpt_borne_et_sans_controle()
    {
        string e = SiteAnalyzer.Excerpt(new string('a', 5000) + "\u0007");
        Assert.AreEqual(1200, e.Length);
        Assert.IsFalse(e.Any(char.IsControl));
    }
}
