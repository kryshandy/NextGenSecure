using System.Text.Json;

namespace CoreGuard.Extension;

/// <summary>Source d'identifiants pour l'auto-remplissage.</summary>
public interface ICredentialProvider
{
    /// <summary>Cherche l'identifiant enregistré pour l'URL (page vérifiée par l'appelant).</summary>
    Task<CoreGuard.Ipc.CredentialLookup> FindAsync(string url, CancellationToken ct = default);
}

/// <summary>Aucun identifiant disponible (tests, coffre non installé).</summary>
public sealed class NullCredentialProvider : ICredentialProvider
{
    public Task<CoreGuard.Ipc.CredentialLookup> FindAsync(string url, CancellationToken ct = default) =>
        Task.FromResult(CoreGuard.Ipc.CredentialLookup.NotFound);
}

/// <summary>
/// Coffre CoreGuard : la demande part vers l'interface (pipe propre à l'utilisateur), qui vérifie que cet hôte a
/// bien été lancé par un navigateur signé avant de répondre. Interface fermée ou coffre verrouillé → « verrouillé ».
/// </summary>
public sealed class VaultCredentialProvider : ICredentialProvider
{
    public Task<CoreGuard.Ipc.CredentialLookup> FindAsync(string url, CancellationToken ct = default) =>
        CoreGuard.Ipc.VaultBroker.FindAsync(url, ct);
}

/// <summary>
/// Route les requêtes de l'extension. Types acceptés (liste blanche) :
/// "checkUrl" {url, hasPassword}, "analyzeCapture" {url, imageBase64} et "requestCredential" {url}.
/// </summary>
public sealed class HostRouter(OcrPhishingAnalyzer analyseur, ICredentialProvider identifiants)
{
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
                "checkUrl" => CheckUrl(requete),
                "analyzeCapture" => await AnalyzeCaptureAsync(requete, ct).ConfigureAwait(false),
                "requestCredential" => await RequestCredentialAsync(requete, ct).ConfigureAwait(false),
                _ => Erreur("Type de requête inconnu.")
            };
        }
        catch (Exception e) when (e is InvalidOperationException or FormatException or ArgumentException
                                      or System.Runtime.InteropServices.COMException)
        {
            // Message générique : aucun détail interne renvoyé à la page/extension.
            return Erreur("Traitement impossible : " + e.GetType().Name);
        }
    }

    // Vérification rapide à chaque navigation (aucune capture) : domaine + signaux d'URL
    private static object CheckUrl(JsonElement requete)
    {
        var url = LireChaine(requete, "url");
        bool motDePasse = requete.TryGetProperty("hasPassword", out var p) && p.ValueKind == JsonValueKind.True;
        var resultat = PhishingLogic.AssessNavigation(url, motDePasse);
        return new { ok = true, verdict = resultat.Verdict.ToString(), reasons = resultat.Reasons };
    }

    private async Task<object> AnalyzeCaptureAsync(JsonElement requete, CancellationToken ct)
    {
        var url = LireChaine(requete, "url");
        var base64 = LireChaine(requete, "imageBase64");
        if (string.IsNullOrEmpty(base64)) return Erreur("imageBase64 manquant.");

        var image = Convert.FromBase64String(base64);
        var resultat = await analyseur.AnalyzeAsync(image, url, ct).ConfigureAwait(false);

        // Le texte OCR n'est pas renvoyé en entier : seules les conclusions utiles à l'UI.
        return new
        {
            ok = true,
            verdict = resultat.Verdict.ToString(),
            reasons = resultat.Reasons,
            qrUrl = resultat.QrUrl
        };
    }

    private async Task<object> RequestCredentialAsync(JsonElement requete, CancellationToken ct)
    {
        var url = LireChaine(requete, "url");
        var hote = PhishingLogic.ExtractHost(url);
        if (hote is null || url is null) return new { ok = true, found = false };
        // Mots de passe uniquement sur une page chiffrée (sauf machine locale pour les tests)
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && hote is not "localhost" and not "127.0.0.1")
            return new { ok = true, found = false, blocked = true };

        // Garde-fou : jamais d'identifiants vers un domaine typosquatté/homographe.
        var domaine = PhishingLogic.GetRegistrableDomain(PhishingLogic.ToSkeleton(hote));
        if (PhishingLogic.DetectTyposquatting(domaine) is not null ||
            PhishingLogic.DetectHomographs(hote).IsSuspicious)
            return new { ok = true, found = false, blocked = true };

        var trouve = await identifiants.FindAsync(url, ct).ConfigureAwait(false);
        return trouve.Found
            ? new { ok = true, found = true, blocked = false, locked = false, username = trouve.Username, password = trouve.Password }
            : new { ok = true, found = false, blocked = trouve.Denied, locked = trouve.Locked, username = (string?)null, password = (string?)null };
    }

    private static string? LireChaine(JsonElement objet, string nom) =>
        objet.TryGetProperty(nom, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static object Erreur(string message) => new { ok = false, error = message };
}
