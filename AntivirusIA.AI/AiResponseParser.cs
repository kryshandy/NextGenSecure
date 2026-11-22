using System.Text.Json;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Ai;

public static class AiResponseParser
{
    // Renvoie null si la réponse est inutilisable : l'appelant gardera alors le verdict local
    public static AiAnalysis? TryParse(string reponse)
    {
        if (string.IsNullOrWhiteSpace(reponse))
            return null;

        // Certains modèles entourent le JSON de ```json ... ``` ou de texte : on isole l'objet { ... }
        int debut = reponse.IndexOf('{');
        int fin = reponse.LastIndexOf('}');
        if (debut < 0 || fin <= debut)
            return null;

        try
        {
            using var doc = JsonDocument.Parse(reponse[debut..(fin + 1)]);
            JsonElement racine = doc.RootElement;

            if (racine.ValueKind != JsonValueKind.Object ||
                !racine.TryGetProperty("verdict", out JsonElement v) ||
                v.ValueKind != JsonValueKind.String)
                return null;

            Verdict? verdict = LireVerdict(v.GetString());
            if (verdict is null)
                return null;

            int confiance = 0;
            if (racine.TryGetProperty("confidence", out JsonElement c) &&
                c.ValueKind == JsonValueKind.Number &&
                c.TryGetDouble(out double valeur))
                confiance = Math.Clamp((int)Math.Round(valeur), 0, 100);

            string? famille = racine.TryGetProperty("family", out JsonElement f) &&
                              f.ValueKind == JsonValueKind.String
                ? f.GetString()
                : null;

            string explication = racine.TryGetProperty("explanation", out JsonElement e) &&
                                 e.ValueKind == JsonValueKind.String
                ? e.GetString() ?? ""
                : "";
            if (explication.Length > 500)
                explication = explication[..500] + "…";

            return new AiAnalysis(verdict.Value, confiance, explication, famille);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static Verdict? LireVerdict(string? texte) => texte?.Trim().ToLowerInvariant() switch
    {
        "sain" or "safe" or "clean" or "benign" => Verdict.Sain,
        "suspect" or "suspicious" => Verdict.Suspect,
        "malveillant" or "malicious" or "malware" => Verdict.Malveillant,
        _ => null
    };
}