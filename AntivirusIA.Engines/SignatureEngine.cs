using System.Text.Json;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Engines;

internal sealed record SignatureEntry(string Sha256, string Name);
internal sealed record SignatureFile(List<SignatureEntry>? Signatures);

/// <summary>
/// Détection par empreinte SHA-256. Les bases sont chargées depuis plusieurs sources :
/// fichiers JSON (<c>{"signatures":[{"sha256","name"}]}</c>) et listes texte (<c>.txt</c>, <c>.sha256</c>),
/// une empreinte par ligne, suivie éventuellement d'un nom ; <c>#</c> introduit un commentaire.
/// Ce format texte accepte directement les exports de flux publics (ex. MalwareBazaar, liste SHA-256).
/// Les lignes invalides sont ignorées : une base mal formée ne doit pas désactiver le moteur.
/// </summary>
public sealed class SignatureEngine : IDetectionEngine
{
    private static readonly string[] Extensions = [".json", ".txt", ".sha256"];

    private readonly Dictionary<string, string> _knownHashes = new(StringComparer.Ordinal);

    public string Name => "Signatures";

    /// <summary>Nombre d'empreintes chargées.</summary>
    public int Count => _knownHashes.Count;

    /// <summary>Charge un fichier de signatures unique (JSON ou liste texte).</summary>
    public SignatureEngine(string signaturesPath) : this([signaturesPath]) { }

    /// <summary>
    /// Charge plusieurs sources : chaque chemin peut être un fichier ou un dossier
    /// (tous les .json/.txt/.sha256 du dossier). Les chemins inexistants sont ignorés,
    /// sauf s'il s'agit de l'unique fichier demandé.
    /// </summary>
    public SignatureEngine(IEnumerable<string> sources)
    {
        var list = sources.ToList();
        foreach (string source in list)
        {
            if (Directory.Exists(source))
            {
                foreach (string f in Directory.EnumerateFiles(source).Where(IsSignatureFile).Order(StringComparer.OrdinalIgnoreCase))
                    LoadFile(f);
            }
            else if (File.Exists(source))
            {
                LoadFile(source);
            }
            else if (list.Count == 1)
            {
                throw new FileNotFoundException("Base de signatures introuvable", source);
            }
        }
    }

    private static bool IsSignatureFile(string path) =>
        Extensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);

    private void LoadFile(string path)
    {
        // JSON reconnu à l'extension ou au contenu (premier caractère significatif '{')
        if (Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase) || LooksLikeJson(path))
            LoadJson(path);
        else
            LoadText(path);
    }

    private static bool LooksLikeJson(string path)
    {
        using var reader = new StreamReader(path);
        int c;
        while ((c = reader.Read()) >= 0)
        {
            if (char.IsWhiteSpace((char)c) || c == '﻿') continue;
            return c == '{';
        }
        return false;
    }

    private void LoadJson(string path)
    {
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        SignatureFile? file;
        try
        {
            file = JsonSerializer.Deserialize<SignatureFile>(File.ReadAllText(path), options);
        }
        catch (JsonException)
        {
            return; // base corrompue : ignorée, les autres sources restent actives
        }

        foreach (var entry in file?.Signatures ?? [])
            Add(entry.Sha256, entry.Name);
    }

    private void LoadText(string path)
    {
        string defaultName = Path.GetFileNameWithoutExtension(path);
        foreach (string raw in File.ReadLines(path))
        {
            string line = raw.Trim();
            int comment = line.IndexOf('#');
            if (comment >= 0) line = line[..comment].Trim();
            if (line.Length == 0) continue;

            // "<sha256>" ou "<sha256> <nom>" ou "<sha256>,<nom>" (CSV simple)
            int sep = line.IndexOfAny([' ', '\t', ',', ';']);
            string hash = sep < 0 ? line : line[..sep];
            string name = sep < 0 ? defaultName : line[(sep + 1)..].Trim().Trim('"');
            Add(hash, name.Length == 0 ? defaultName : name);
        }
    }

    private void Add(string? hash, string? name)
    {
        if (hash is null || hash.Length != 64 || !hash.All(Uri.IsHexDigit)) return;
        _knownHashes[hash.ToLowerInvariant()] = string.IsNullOrWhiteSpace(name) ? "Malware-Generic" : Sanitize(name);
    }

    // Les noms proviennent de flux externes : on ne garde que de l'ASCII imprimable, longueur bornée
    private static string Sanitize(string value)
    {
        var chars = value.Where(c => c is >= ' ' and <= '~').Take(128).ToArray();
        return chars.Length == 0 ? "Malware-Generic" : new string(chars);
    }

    public async Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default)
    {
        report.Sha256 ??= await FileHasher.ComputeSha256Async(report.FullPath, ct);

        var indicators = new List<Indicator>();
        if (_knownHashes.TryGetValue(report.Sha256, out string? malwareName))
            indicators.Add(new Indicator(Name, $"Signature connue : {malwareName}", 100, Definitive: true));

        return indicators;
    }
}
