using System.Text;
using System.Text.RegularExpressions;
using AntivirusIA.Core.Models;
using AntivirusIA.Engines;
using CoreGuard.Ipc;

namespace CoreGuard.Service;

/// <summary>
/// Analyse des contenus soumis par le fournisseur AMSI. AMSI transmet le script tel qu'il va être exécuté
/// (pour PowerShell : chaque bloc après décodage de -EncodedCommand et des concaténations). On ajoute une
/// couche de désobfuscation : les blobs Base64 du script sont décodés et analysés à leur tour.
/// Blocage si une règle « preuve forte » correspond ou si le score atteint <see cref="BlockScore"/>.
/// </summary>
public sealed partial class ScriptScanner(PatternRuleEngine rules)
{
    public const int BlockScore = 60;
    public const int SuspectScore = 30;
    public const int MaxContentBytes = 512 * 1024;
    private const int MaxDecodedBlobs = 16;

    public AmsiVerdict Evaluate(AmsiScanRequest? request)
    {
        if (request is null || string.IsNullOrEmpty(request.Content)) return new AmsiVerdict(false, 0, "Contenu vide.");

        byte[] raw;
        try { raw = Convert.FromBase64String(request.Content); }
        catch (FormatException) { return new AmsiVerdict(false, 0, "Contenu illisible."); }
        if (raw.Length > MaxContentBytes) raw = raw[..MaxContentBytes];

        string text = Decode(raw);
        var indicators = new List<Indicator>(rules.Evaluate(Encoding.UTF8.GetBytes(text)));

        // Désobfuscation : blobs Base64 décodés (UTF-16LE comme -EncodedCommand, ou UTF-8)
        foreach (string decoded in DecodeBase64Blobs(text))
        {
            foreach (var i in rules.Evaluate(Encoding.UTF8.GetBytes(decoded)))
                indicators.Add(i with { Description = i.Description + " (dans du Base64 décodé)" });
        }

        // Une même règle trouvée en clair et dans un blob ne compte qu'une fois
        var distinct = indicators.GroupBy(i => i.Description.Split(" (dans du Base64")[0]).Select(g => g.First()).ToList();
        int score = Math.Min(100, distinct.Sum(i => i.Points));
        bool detected = distinct.Any(i => i.Definitive) || score >= BlockScore;

        string reason = distinct.Count == 0
            ? "Aucune règle"
            : string.Join(" ; ", distinct.OrderByDescending(i => i.Points).Take(3).Select(i => i.Description));
        return new AmsiVerdict(detected, score, reason);
    }

    /// <summary>UTF-16LE si le contenu en a la forme (octets nuls aux positions impaires), sinon UTF-8.</summary>
    internal static string Decode(byte[] raw)
    {
        if (raw.Length >= 4 && raw.Length % 2 == 0)
        {
            int sample = Math.Min(raw.Length, 512) & ~1, zeros = 0;
            for (int i = 1; i < sample; i += 2) if (raw[i] == 0) zeros++;
            if (zeros >= sample / 2 * 0.6) return Encoding.Unicode.GetString(raw);
        }
        return Encoding.UTF8.GetString(raw);
    }

    internal static IEnumerable<string> DecodeBase64Blobs(string text)
    {
        int count = 0;
        foreach (Match m in Base64Blob().Matches(text))
        {
            if (++count > MaxDecodedBlobs) yield break;
            byte[] bytes;
            try { bytes = Convert.FromBase64String(m.Value); }
            catch (FormatException) { continue; }
            string decoded = Decode(bytes);
            // On ne garde que ce qui ressemble à du texte (évite d'analyser des images encodées)
            if (decoded.Count(c => !char.IsControl(c) || char.IsWhiteSpace(c)) >= decoded.Length * 0.9)
                yield return decoded;
        }
    }

    [GeneratedRegex("[A-Za-z0-9+/]{24,}={0,2}")]
    private static partial Regex Base64Blob();
}
