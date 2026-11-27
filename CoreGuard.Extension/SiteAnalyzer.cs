namespace CoreGuard.Extension;

/// <summary>Décision sur un site : verdict des règles, place dans la base de confiance, besoin d'OCR ou de revue par l'IA.</summary>
public sealed record SiteDecision(
    PhishingVerdict Verdict,
    IReadOnlyList<string> Reasons,
    string Domain,
    SiteTrust Trust,
    bool NeedsCapture,
    bool NeedsReview,
    IReadOnlyList<string> Brands,
    bool LoginPage,
    IReadOnlyList<string>? OwnBrands = null);

/// <summary>
/// Cascade de décision anti-phishing, de la plus rapide à la plus coûteuse (logique pure, testable) :
/// <list type="number">
/// <item>site déclaré de confiance par l'utilisateur → sûr (seul l'utilisateur peut « remonter » un site) ;</item>
/// <item>liste noire → phishing immédiat ;</item>
/// <item>domaine connu (100 000 plus visités, hors hébergeurs partagés) → sûr, sans capture ni OCR ;</item>
/// <item>sinon règles (homographes, typosquatting, marque en sous-domaine, IP, http) puis, s'il y a un formulaire de
///       connexion, capture + OCR (marque affichée vs domaine réel) ;</item>
/// <item>zone grise (domaine inconnu ou hébergeur partagé, avec connexion ou marque) → revue par l'IA locale, qui ne
///       peut qu'aggraver le verdict.</item>
/// </list>
/// </summary>
public sealed class SiteAnalyzer(TrustBase trust)
{
    private const int MaxExcerpt = 1200;

    public TrustBase Trust => trust;

    /// <summary>À chaque navigation, sans capture.</summary>
    public SiteDecision CheckNavigation(string? url, bool hasPassword)
    {
        string? host = PhishingLogic.ExtractHost(url);
        if (host is null || url is null)
            return new SiteDecision(PhishingVerdict.Safe, ["URL non analysable (schéma non web ou invalide)."], "", SiteTrust.Unknown, false, false, [], false);

        string domain = trust.RegistrableDomain(host);
        var level = trust.Classify(url, host);
        switch (level)
        {
            case SiteTrust.UserTrusted:
                return new SiteDecision(PhishingVerdict.Safe, ["Site déclaré de confiance par vous dans CoreGuard."], domain, level, false, false, [], hasPassword);
            case SiteTrust.Blocklisted:
                return new SiteDecision(PhishingVerdict.Phishing, ["Adresse en liste noire de phishing (OpenPhish ou votre liste personnelle)."], domain, level, false, false, [], hasPassword);
            case SiteTrust.Known:
                return new SiteDecision(PhishingVerdict.Safe, ["Site connu (parmi les 100 000 domaines les plus visités)."], domain, level, false, false, [], hasPassword);
        }

        var rules = PhishingLogic.AssessNavigation(url, hasPassword);
        var reasons = new List<string>(rules.Reasons);
        var verdict = rules.Verdict;
        if (level == SiteTrust.ContentHost)
        {
            reasons.Add("Page hébergée sur un service où n'importe qui peut publier : la réputation du service ne garantit rien.");
            if (hasPassword && verdict == PhishingVerdict.Safe)
            {
                verdict = PhishingVerdict.Suspicious;
                reasons.Add("Un mot de passe est demandé sur une page d'hébergement gratuit.");
            }
        }
        else
        {
            reasons.Add("Domaine absent de la base de confiance (site peu connu).");
        }
        return new SiteDecision(verdict, reasons, domain, level, NeedsCapture: hasPassword, NeedsReview: false, [], hasPassword);
    }

    /// <summary>Après capture : texte lu par OCR (non fiable) corrélé au domaine réel.</summary>
    public SiteDecision CheckPage(string? url, string ocrText, bool hasPassword)
    {
        var nav = CheckNavigation(url, hasPassword);
        // Marques affichées : « étrangères » au domaine (indice d'usurpation) ou propres au domaine (page officielle)
        var cited = PhishingLogic.FindBrandsInText(ocrText ?? string.Empty);
        var own = cited.Where(b => PhishingLogic.IsLegitimateDomainForBrand(b, nav.Domain)).ToList();
        var brands = cited.Except(own).ToList();
        bool login = hasPassword || PhishingLogic.LooksLikeLoginPage(ocrText ?? string.Empty);
        if (nav.Trust is SiteTrust.UserTrusted or SiteTrust.Blocklisted or SiteTrust.Known || nav.Domain.Length == 0)
            return nav with { Brands = brands, OwnBrands = own, LoginPage = login, NeedsCapture = false };

        var text = PhishingLogic.Assess(ocrText ?? string.Empty, url, hasPassword);
        var verdict = text.Verdict > nav.Verdict ? text.Verdict : nav.Verdict;
        var reasons = nav.Reasons.Concat(text.Reasons).Distinct().ToList();
        // Revue par l'IA seulement s'il y a matière à aggraver (marque usurpée, données sensibles) ou un verdict à expliquer :
        // une page sans marque qui demande juste un identifiant n'est pas soumise au modèle
        bool review = own.Count == 0 && (brands.Count > 0 || CoreGuard.Ipc.SiteReview.HasSensitiveRequest(ocrText) || verdict != PhishingVerdict.Safe);
        return new SiteDecision(verdict, reasons, nav.Domain, nav.Trust, false, review, brands, login, own);
    }

    /// <summary>Extrait borné du texte de la page, transmis à l'IA (sans caractères de contrôle).</summary>
    public static string Excerpt(string ocrText)
    {
        var clean = new string((ocrText ?? string.Empty).Select(c => char.IsControl(c) ? ' ' : c).ToArray());
        clean = string.Join(' ', clean.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        return clean.Length > MaxExcerpt ? clean[..MaxExcerpt] : clean;
    }

    /// <summary>Le plus grave de deux verdicts.</summary>
    public static PhishingVerdict Worst(PhishingVerdict a, PhishingVerdict b) => a > b ? a : b;
}
