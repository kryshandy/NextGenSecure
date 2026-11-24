using System.Text.Json;

namespace CoreGuard.Extension;

/// <summary>Source d'identifiants (sera branchée sur le coffre par la composition root).</summary>
public interface ICredentialProvider
{
    /// <summary>Retourne (identifiant, mot de passe) pour l'hôte donné, ou null si aucun.</summary>
    (string Username, string Password)? Find(string host);
}

/// <summary>Implémentation par défaut : aucun identifiant disponible.</summary>
public sealed class NullCredentialProvider : ICredentialProvider
{
    public (string Username, string Password)? Find(string host) => null;
}

/// <summary>
/// Route les requêtes de l'extension. Types acceptés (liste blanche) :
/// "analyzeCapture" {url, imageBase64} et "requestCredential" {url}.
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
                "analyzeCapture" => await AnalyzeCaptureAsync(requete, ct).ConfigureAwait(false),
                "requestCredential" => RequestCredential(requete),
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

    private object RequestCredential(JsonElement requete)
    {
        var hote = PhishingLogic.ExtractHost(LireChaine(requete, "url"));
        if (hote is null) return new { ok = true, found = false };

        // Garde-fou : jamais d'identifiants vers un domaine typosquatté/homographe.
        var domaine = PhishingLogic.GetRegistrableDomain(PhishingLogic.ToSkeleton(hote));
        if (PhishingLogic.DetectTyposquatting(domaine) is not null ||
            PhishingLogic.DetectHomographs(hote).IsSuspicious)
            return new { ok = true, found = false, blocked = true };

        var trouve = identifiants.Find(hote);
        return trouve is null
            ? new { ok = true, found = false, blocked = false }
            : new { ok = true, found = true, blocked = false, username = trouve.Value.Username, password = trouve.Value.Password };
    }

    private static string? LireChaine(JsonElement objet, string nom) =>
        objet.TryGetProperty(nom, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static object Erreur(string message) => new { ok = false, error = message };
}
