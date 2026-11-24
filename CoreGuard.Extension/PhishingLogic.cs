using System.Globalization;
using System.Text;

namespace CoreGuard.Extension;

/// <summary>Verdict d'une analyse anti-phishing.</summary>
public enum PhishingVerdict
{
    Safe,
    Suspicious,
    Phishing
}

/// <summary>Résultat d'analyse : verdict + raisons lisibles.</summary>
public sealed record PhishingAssessment(PhishingVerdict Verdict, IReadOnlyList<string> Reasons);

/// <summary>Résultat de la détection d'homographes.</summary>
public sealed record HomographResult(bool IsSuspicious, bool MixedScripts, IReadOnlyList<char> Characters);

/// <summary>
/// Logique PURE (sans E/S, sans WinRT) de détection de phishing : testable unitairement.
/// Toutes les entrées (texte OCR, URL) sont considérées comme NON FIABLES.
/// </summary>
public static class PhishingLogic
{
    /// <summary>Marques surveillées -> domaines enregistrables légitimes.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> Brands =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["google"] = ["google.com", "google.fr", "gstatic.com", "googleapis.com", "youtube.com"],
            ["microsoft"] = ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"],
            ["paypal"] = ["paypal.com", "paypal.fr"],
            ["apple"] = ["apple.com", "icloud.com"],
            ["amazon"] = ["amazon.com", "amazon.fr"],
            ["facebook"] = ["facebook.com", "fb.com"],
            ["bnpparibas"] = ["bnpparibas.com", "bnpparibas.net", "mabanque.bnpparibas"],
            ["societegenerale"] = ["societegenerale.fr", "societegenerale.com", "sg.fr"],
            ["creditagricole"] = ["credit-agricole.fr", "credit-agricole.com"],
            ["labanquepostale"] = ["labanquepostale.fr"],
            ["hsbc"] = ["hsbc.com", "hsbc.fr"],
            ["chase"] = ["chase.com"],
            ["wellsfargo"] = ["wellsfargo.com"]
        };

    /// <summary>Alias texte (tel qu'affiché à l'écran, normalisé) -> clé de marque.</summary>
    private static readonly (string Alias, string Brand)[] BrandAliases =
    [
        ("google", "google"), ("microsoft", "microsoft"), ("paypal", "paypal"),
        ("apple id", "apple"), ("icloud", "apple"), ("amazon", "amazon"), ("facebook", "facebook"),
        ("bnp paribas", "bnpparibas"), ("societe generale", "societegenerale"),
        ("credit agricole", "creditagricole"), ("la banque postale", "labanquepostale"),
        ("hsbc", "hsbc"), ("chase", "chase"), ("wells fargo", "wellsfargo")
    ];

    private static readonly string[] LoginKeywords =
    [
        "sign in", "log in", "login", "password", "mot de passe", "connexion", "se connecter",
        "identifiant", "verify your account", "verifiez votre compte"
    ];

    /// <summary>Suffixes à deux niveaux courants (liste réduite, volontairement minimale).</summary>
    private static readonly HashSet<string> TwoLevelSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.za", "com.fr"
    };

    /// <summary>Table minimale de confusables cyrilliques/grecs -> équivalent latin.</summary>
    private static readonly Dictionary<char, char> Confusables = new()
    {
        // Cyrillique
        ['а'] = 'a', ['е'] = 'e', ['о'] = 'o', ['р'] = 'p', ['с'] = 'c', ['у'] = 'y', ['х'] = 'x',
        ['і'] = 'i', ['ј'] = 'j', ['ѕ'] = 's', ['ԁ'] = 'd', ['һ'] = 'h', ['ԛ'] = 'q', ['ԝ'] = 'w',
        ['А'] = 'A', ['В'] = 'B', ['Е'] = 'E', ['К'] = 'K', ['М'] = 'M', ['Н'] = 'H', ['О'] = 'O',
        ['Р'] = 'P', ['С'] = 'C', ['Т'] = 'T', ['Х'] = 'X',
        // Grec
        ['α'] = 'a', ['ο'] = 'o', ['ρ'] = 'p', ['ν'] = 'v', ['ι'] = 'i', ['κ'] = 'k', ['τ'] = 't', ['υ'] = 'u',
        ['Α'] = 'A', ['Β'] = 'B', ['Ε'] = 'E', ['Η'] = 'H', ['Ι'] = 'I', ['Κ'] = 'K', ['Μ'] = 'M',
        ['Ν'] = 'N', ['Ο'] = 'O', ['Ρ'] = 'P', ['Τ'] = 'T', ['Χ'] = 'X', ['Υ'] = 'Y', ['Ζ'] = 'Z'
    };

    // ---------------------------------------------------------------- Levenshtein

    /// <summary>Distance de Levenshtein (insertions, suppressions, substitutions).</summary>
    public static int Levenshtein(string a, string b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        if (a.Length == 0) return b.Length;
        if (b.Length == 0) return a.Length;

        // Deux lignes seulement : mémoire O(min(n, m)).
        var precedente = new int[b.Length + 1];
        var courante = new int[b.Length + 1];
        for (var j = 0; j <= b.Length; j++) precedente[j] = j;

        for (var i = 1; i <= a.Length; i++)
        {
            courante[0] = i;
            for (var j = 1; j <= b.Length; j++)
            {
                var cout = a[i - 1] == b[j - 1] ? 0 : 1;
                courante[j] = Math.Min(Math.Min(courante[j - 1] + 1, precedente[j] + 1), precedente[j - 1] + cout);
            }
            (precedente, courante) = (courante, precedente);
        }
        return precedente[b.Length];
    }

    // ---------------------------------------------------------------- Homographes

    private static bool EstCyrillique(char c) => c >= 'Ѐ' && c <= 'ԯ';
    private static bool EstGrec(char c) => (c >= 'Ͱ' && c <= 'Ͽ') || (c >= 'ἀ' && c <= '῿');
    private static bool EstLatinAscii(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

    /// <summary>
    /// Détecte les caractères cyrilliques/grecs déguisés en lettres latines. Suspect si un tel
    /// caractère figure dans un mot mêlant aussi des lettres latines (mélange d'alphabets),
    /// ou si un confusable connu apparaît.
    /// </summary>
    public static HomographResult DetectHomographs(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var trouves = new List<char>();
        var melange = false;

        // On raisonne mot par mot : un mot 100 % cyrillique (ex. texte russe) n'est pas un homographe.
        foreach (var mot in text.Split(['.', ' ', '-', '/', ':', '@'], StringSplitOptions.RemoveEmptyEntries))
        {
            var aLatin = mot.Any(EstLatinAscii);
            var aAutre = mot.Any(c => EstCyrillique(c) || EstGrec(c));
            if (!aAutre) continue;
            if (aLatin)
            {
                melange = true;
                trouves.AddRange(mot.Where(c => (EstCyrillique(c) || EstGrec(c)) && Confusables.ContainsKey(c)));
            }
            else if (mot.All(c => Confusables.ContainsKey(c) || !char.IsLetter(c)))
            {
                // Mot entièrement composé de confusables : se lit comme du latin (ex. "раураl" tout cyrillique).
                trouves.AddRange(mot.Where(Confusables.ContainsKey));
            }
        }

        return new HomographResult(trouves.Count > 0, melange, trouves.Distinct().ToList());
    }

    /// <summary>Remplace les confusables par leur équivalent latin (squelette de comparaison).</summary>
    public static string ToSkeleton(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var sb = new StringBuilder(text.Length);
        foreach (var c in text)
            sb.Append(Confusables.TryGetValue(c, out var latin) ? latin : c);
        return sb.ToString();
    }

    // ---------------------------------------------------------------- Domaines

    /// <summary>Extrait l'hôte (minuscule) d'une URL http(s) ; null si invalide ou schéma non web.</summary>
    public static string? ExtractHost(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)) return null;
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return null;
        // IdnHost renvoie la forme punycode ; Host la forme Unicode (utile pour les homographes).
        return uri.Host.ToLowerInvariant();
    }

    /// <summary>Domaine enregistrable approximatif (eTLD+1) d'un hôte.</summary>
    public static string GetRegistrableDomain(string host)
    {
        ArgumentNullException.ThrowIfNull(host);
        var labels = host.Trim('.').ToLowerInvariant().Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length <= 2) return string.Join('.', labels);
        var deuxDerniers = $"{labels[^2]}.{labels[^1]}";
        return TwoLevelSuffixes.Contains(deuxDerniers)
            ? string.Join('.', labels[^3..])
            : deuxDerniers;
    }

    /// <summary>Le domaine appartient-il (exactement) à la liste légitime d'une marque ?</summary>
    public static bool IsLegitimateDomainForBrand(string brand, string registrableDomain) =>
        Brands.TryGetValue(brand, out var domaines) &&
        domaines.Contains(registrableDomain, StringComparer.OrdinalIgnoreCase);

    // ---------------------------------------------------------------- Typosquatting

    /// <summary>
    /// Typosquatting : le libellé principal du domaine ressemble à une marque (distance 1 ou 2)
    /// sans être le domaine légitime. Retourne la marque imitée, ou null.
    /// </summary>
    public static string? DetectTyposquatting(string registrableDomain)
    {
        ArgumentNullException.ThrowIfNull(registrableDomain);
        var domaine = ToSkeleton(registrableDomain.ToLowerInvariant());
        var libelle = domaine.Split('.')[0].Replace("-", "");
        if (libelle.Length < 4) return null; // trop court : trop de faux positifs

        foreach (var marque in Brands.Keys)
        {
            if (IsLegitimateDomainForBrand(marque, domaine)) return null;
            var d = Levenshtein(libelle, marque);
            // Tolérance proportionnelle : 1 faute pour les noms courts, 2 pour les longs.
            var seuil = marque.Length >= 8 ? 2 : 1;
            if (d >= 1 && d <= seuil) return marque;
            // Marque + mot ajouté (ex. "paypal-secure", "google-login") sur un domaine non légitime.
            if (d > seuil && libelle.Contains(marque, StringComparison.Ordinal)) return marque;
        }
        return null;
    }

    // ---------------------------------------------------------------- Corrélation

    /// <summary>Normalise un texte OCR : minuscule, sans accents, squelette latin, espaces compactés.</summary>
    public static string NormalizeText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var decompose = ToSkeleton(text).Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder(decompose.Length);
        foreach (var c in decompose)
            if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
                sb.Append(char.IsWhiteSpace(c) ? ' ' : char.ToLowerInvariant(c));
        return string.Join(' ', sb.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary>Marques évoquées par un texte visible (après normalisation).</summary>
    public static IReadOnlyList<string> FindBrandsInText(string ocrText)
    {
        var texte = NormalizeText(ocrText);
        return BrandAliases.Where(a => texte.Contains(a.Alias, StringComparison.Ordinal))
            .Select(a => a.Brand).Distinct().ToList();
    }

    /// <summary>Le texte évoque-t-il une connexion / saisie d'identifiants ?</summary>
    public static bool LooksLikeLoginPage(string ocrText)
    {
        var texte = NormalizeText(ocrText);
        return LoginKeywords.Any(k => texte.Contains(k, StringComparison.Ordinal));
    }

    /// <summary>
    /// Corrélation texte visible / domaine réel :
    /// - homographe ou typosquatting sur le domaine -> alerte quel que soit le texte ;
    /// - marque connue affichée sur une page de connexion dont le domaine n'est pas celui de la marque -> phishing.
    /// </summary>
    public static PhishingAssessment Assess(string ocrText, string? pageUrl)
    {
        var raisons = new List<string>();
        var verdict = PhishingVerdict.Safe;

        var hote = ExtractHost(pageUrl);
        if (hote is null)
            return new PhishingAssessment(PhishingVerdict.Safe, ["URL non analysable (schéma non web ou invalide)."]);

        var homographes = DetectHomographs(hote);
        if (homographes.IsSuspicious || hote.Contains("xn--", StringComparison.Ordinal))
        {
            verdict = PhishingVerdict.Phishing;
            raisons.Add("Domaine avec caractères homographes (cyrillique/grec) ou punycode.");
        }

        var domaine = GetRegistrableDomain(ToSkeleton(hote));
        var imitee = DetectTyposquatting(domaine);
        if (imitee is not null)
        {
            verdict = PhishingVerdict.Phishing;
            raisons.Add($"Typosquatting probable de la marque '{imitee}' ({domaine}).");
        }

        var marques = FindBrandsInText(ocrText);
        var connexion = LooksLikeLoginPage(ocrText);
        foreach (var marque in marques)
        {
            if (IsLegitimateDomainForBrand(marque, domaine)) continue;
            if (connexion)
            {
                verdict = PhishingVerdict.Phishing;
                raisons.Add($"La page évoque '{marque}' et demande une connexion mais le domaine est '{domaine}'.");
            }
            else if (verdict == PhishingVerdict.Safe)
            {
                verdict = PhishingVerdict.Suspicious;
                raisons.Add($"La page évoque '{marque}' sur un domaine tiers '{domaine}'.");
            }
        }

        return new PhishingAssessment(verdict, raisons);
    }

    /// <summary>Évalue uniquement une URL (cas du QR code : aucun texte de page disponible).</summary>
    public static PhishingAssessment AssessUrl(string? url) => Assess(string.Empty, url);
}
