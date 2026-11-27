using System.Text.Json;
using CoreGuard.Ipc;

namespace CoreGuard.Extension;

/// <summary>Source d'identifiants pour l'auto-remplissage.</summary>
public interface ICredentialProvider
{
    /// <summary>Cherche l'identifiant enregistré pour l'URL (page vérifiée par l'appelant).</summary>
    Task<CredentialLookup> FindAsync(string url, CancellationToken ct = default);
}

/// <summary>Aucun identifiant disponible (tests, coffre non installé).</summary>
public sealed class NullCredentialProvider : ICredentialProvider
{
    public Task<CredentialLookup> FindAsync(string url, CancellationToken ct = default) =>
        Task.FromResult(CredentialLookup.NotFound);
}

/// <summary>
/// Coffre CoreGuard : la demande part vers l'interface (pipe propre à l'utilisateur), qui vérifie que cet hôte a
/// bien été lancé par un navigateur signé avant de répondre. Interface fermée ou coffre verrouillé → « verrouillé ».
/// </summary>
public sealed class VaultCredentialProvider : ICredentialProvider
{
    public Task<CredentialLookup> FindAsync(string url, CancellationToken ct = default) =>
        VaultBroker.FindAsync(url, ct);
}

/// <summary>Relais vers l'application CoreGuard : journal des verdicts, revue par l'IA, confirmation de confiance.</summary>
public interface ISiteRelay
{
    Task<SiteReply> SendAsync(string type, SiteFacts facts, CancellationToken ct = default);
}

/// <summary>Relais par le pipe de l'utilisateur (application fermée → « injoignable », les règles restent appliquées).</summary>
public sealed class PipeSiteRelay : ISiteRelay
{
    public Task<SiteReply> SendAsync(string type, SiteFacts facts, CancellationToken ct = default) =>
        VaultBroker.SendSiteAsync(type, facts, type switch
        {
            "report" => TimeSpan.FromSeconds(2),
            "review" => TimeSpan.FromSeconds(50),
            _ => TimeSpan.FromMinutes(2)
        }, ct);
}

/// <summary>Aucune application joignable (tests).</summary>
public sealed class NullSiteRelay : ISiteRelay
{
    public Task<SiteReply> SendAsync(string type, SiteFacts facts, CancellationToken ct = default) =>
        Task.FromResult(SiteReply.NotReachable(facts.Verdict));
}

/// <summary>
/// Route les requêtes de l'extension. Types acceptés (liste blanche) :
/// "checkUrl" {url, hasPassword}, "analyzeCapture" {url, imageBase64, hasPassword}, "reviewSite" {facts},
/// "trustSite" {url} et "requestCredential" {url}.
/// </summary>
public sealed class HostRouter
{
    private readonly OcrPhishingAnalyzer _ocr;
    private readonly ICredentialProvider _credentials;
    private readonly SiteAnalyzer _sites;
    private readonly ISiteRelay _relay;

    public HostRouter(OcrPhishingAnalyzer analyseur, ICredentialProvider identifiants, SiteAnalyzer? sites = null, ISiteRelay? relay = null)
    {
        _ocr = analyseur;
        _credentials = identifiants;
        _sites = sites ?? new SiteAnalyzer(new TrustBase(PublicSuffixList.Parse([]), [], [], []));
        _relay = relay ?? new NullSiteRelay();
    }

    public async Task<object> HandleAsync(JsonElement requete, CancellationToken ct = default)
    {
        if (requete.ValueKind != JsonValueKind.Object ||
            !requete.TryGetProperty("type", out var typeProp) ||
            typeProp.ValueKind != JsonValueKind.String)
            return Erreur("Requête invalide.");

        try
        {
            return typeProp.GetString() switch
            {
                "checkUrl" => await CheckUrlAsync(requete, ct).ConfigureAwait(false),
                "analyzeCapture" => await AnalyzeCaptureAsync(requete, ct).ConfigureAwait(false),
                "reviewSite" => await ReviewSiteAsync(requete, ct).ConfigureAwait(false),
                "trustSite" => await TrustSiteAsync(requete, ct).ConfigureAwait(false),
                "requestCredential" => await RequestCredentialAsync(requete, ct).ConfigureAwait(false),
                _ => Erreur("Type de requête inconnu.")
            };
        }
        catch (Exception e) when (e is InvalidOperationException or FormatException or ArgumentException or JsonException
                                      or System.Runtime.InteropServices.COMException)
        {
            // Message générique : aucun détail interne renvoyé à la page/extension.
            return Erreur("Traitement impossible : " + e.GetType().Name);
        }
    }

    // Vérification rapide à chaque navigation (aucune capture) : base de confiance + signaux d'URL
    private async Task<object> CheckUrlAsync(JsonElement requete, CancellationToken ct)
    {
        var url = LireChaine(requete, "url");
        bool motDePasse = requete.TryGetProperty("hasPassword", out var p) && p.ValueKind == JsonValueKind.True;
        var d = _sites.CheckNavigation(url, motDePasse);
        await ReportAsync(url, d, "", ct).ConfigureAwait(false);
        return new { ok = true, verdict = d.Verdict.ToString(), reasons = d.Reasons, trust = d.Trust.ToString(), needsCapture = d.NeedsCapture };
    }

    private async Task<object> AnalyzeCaptureAsync(JsonElement requete, CancellationToken ct)
    {
        var url = LireChaine(requete, "url");
        var base64 = LireChaine(requete, "imageBase64");
        if (string.IsNullOrEmpty(base64)) return Erreur("imageBase64 manquant.");
        bool motDePasse = !requete.TryGetProperty("hasPassword", out var p) || p.ValueKind != JsonValueKind.False;

        var (texte, urlQr) = await _ocr.ReadAsync(Convert.FromBase64String(base64), ct).ConfigureAwait(false);
        var d = _sites.CheckPage(url, texte, motDePasse);
        var verdict = d.Verdict;
        var raisons = new List<string>(d.Reasons);

        // Quishing : un QR code visible peut cacher une URL malveillante.
        if (urlQr is not null)
        {
            var qr = _sites.CheckNavigation(urlQr, false);
            var qrRules = PhishingLogic.AssessUrl(urlQr);
            var qrVerdict = SiteAnalyzer.Worst(qr.Trust == SiteTrust.Known ? PhishingVerdict.Safe : qrRules.Verdict, qr.Verdict);
            verdict = SiteAnalyzer.Worst(verdict, qrVerdict);
            raisons.AddRange((qrVerdict == PhishingVerdict.Safe ? [] : qr.Reasons.Concat(qrRules.Reasons)).Distinct().Select(r => "[QR] " + r));
            raisons.Add("[QR] URL cachée dans un QR code : " + urlQr);
        }
        d = d with { Verdict = verdict, Reasons = raisons };

        string excerpt = SiteAnalyzer.Excerpt(texte);
        await ReportAsync(url, d, excerpt, ct).ConfigureAwait(false);

        // Le texte OCR n'est pas renvoyé en entier : seules les conclusions, plus les faits pour la revue par l'IA.
        return new
        {
            ok = true,
            verdict = d.Verdict.ToString(),
            reasons = d.Reasons,
            qrUrl = urlQr,
            trust = d.Trust.ToString(),
            review = d.NeedsReview && url is not null ? Facts(url, d, excerpt) : null
        };
    }

    // Revue par l'IA locale (dans l'application) : le verdict renvoyé n'est jamais plus clément que celui des règles
    private async Task<object> ReviewSiteAsync(JsonElement requete, CancellationToken ct)
    {
        if (!requete.TryGetProperty("facts", out var f) || f.ValueKind != JsonValueKind.Object) return Erreur("facts manquant.");
        var facts = f.Deserialize<SiteFacts>(JsonOptions);
        if (facts is null || PhishingLogic.ExtractHost(facts.Url) is not { } host) return Erreur("facts invalide.");

        // Les faits viennent de l'extension : on recalcule ce qui peut l'être (domaine, base de confiance, règles d'URL)
        var nav = _sites.CheckNavigation(facts.Url, facts.LoginPage);
        var rules = Enum.TryParse<PhishingVerdict>(facts.Verdict, out var v) ? SiteAnalyzer.Worst(v, nav.Verdict) : nav.Verdict;
        if (nav.Trust is SiteTrust.UserTrusted or SiteTrust.Known)
            return new { ok = true, verdict = nav.Verdict.ToString(), explanation = (string?)null, aiUsed = false, unavailable = false };

        facts = facts with { Domain = _sites.Trust.RegistrableDomain(host), Verdict = rules.ToString(), KnownDomain = false };
        var reply = await _relay.SendAsync("review", facts, ct).ConfigureAwait(false);
        var final = Enum.TryParse<PhishingVerdict>(reply.Verdict, out var ai) ? SiteAnalyzer.Worst(rules, ai) : rules;
        return new { ok = true, verdict = final.ToString(), explanation = reply.Explanation, aiUsed = reply.AiUsed, unavailable = reply.Unavailable };
    }

    // « Je fais confiance à ce site » : seule l'application, après confirmation de l'utilisateur, l'enregistre
    private async Task<object> TrustSiteAsync(JsonElement requete, CancellationToken ct)
    {
        var url = LireChaine(requete, "url");
        if (PhishingLogic.ExtractHost(url) is not { } host || url is null) return Erreur("URL invalide.");
        var d = _sites.CheckNavigation(url, false);
        var reply = await _relay.SendAsync("trust", Facts(url, d, ""), ct).ConfigureAwait(false);
        return new { ok = true, accepted = reply.Accepted, unavailable = reply.Unavailable, domain = _sites.Trust.RegistrableDomain(host) };
    }

    private async Task<object> RequestCredentialAsync(JsonElement requete, CancellationToken ct)
    {
        var url = LireChaine(requete, "url");
        var hote = PhishingLogic.ExtractHost(url);
        if (hote is null || url is null) return new { ok = true, found = false };
        // Mots de passe uniquement sur une page chiffrée (sauf machine locale pour les tests)
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && hote is not "localhost" and not "127.0.0.1")
            return new { ok = true, found = false, blocked = true };

        // Garde-fou : jamais d'identifiants vers un domaine typosquatté/homographe ou en liste noire.
        var domaine = PhishingLogic.GetRegistrableDomain(PhishingLogic.ToSkeleton(hote));
        if (PhishingLogic.DetectTyposquatting(domaine) is not null ||
            PhishingLogic.DetectHomographs(hote).IsSuspicious ||
            _sites.Trust.IsBlocklisted(url, hote))
            return new { ok = true, found = false, blocked = true };

        var trouve = await _credentials.FindAsync(url, ct).ConfigureAwait(false);
        return trouve.Found
            ? new { ok = true, found = true, blocked = false, locked = false, username = trouve.Username, password = trouve.Password }
            : new { ok = true, found = false, blocked = trouve.Denied, locked = trouve.Locked, username = (string?)null, password = (string?)null };
    }

    // Tout verdict non sûr est journalisé dans l'application (tableau de bord, bulle Windows si elle est cachée)
    private async Task ReportAsync(string? url, SiteDecision d, string excerpt, CancellationToken ct)
    {
        if (url is null || d.Verdict == PhishingVerdict.Safe) return;
        await _relay.SendAsync("report", Facts(url, d, excerpt), ct).ConfigureAwait(false);
    }

    private static SiteFacts Facts(string url, SiteDecision d, string excerpt) =>
        new(url.Length > 2000 ? url[..2000] : url, d.Domain, d.Verdict.ToString(), d.Reasons.Take(12).ToList(),
            d.Brands.Take(12).ToList(), d.LoginPage, d.Trust == SiteTrust.Known, excerpt, (d.OwnBrands ?? []).Take(12).ToList());

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static string? LireChaine(JsonElement objet, string nom) =>
        objet.TryGetProperty(nom, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static object Erreur(string message) => new { ok = false, error = message };
}
