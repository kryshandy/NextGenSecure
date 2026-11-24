using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Engines;

/// <summary>Motif recherché : texte (ASCII, option insensible à la casse / UTF-16LE) ou hexadécimal avec jokers <c>??</c>.</summary>
public sealed record PatternString(string? Text = null, string? Hex = null, bool NoCase = false, bool Wide = false);

/// <summary>
/// Règle de contenu inspirée de YARA : <see cref="Condition"/> vaut "any", "all" ou un nombre minimal de motifs trouvés.
/// <see cref="Definitive"/> : la règle identifie une menace précise (non atténuée par la signature numérique).
/// </summary>
public sealed record PatternRule(
    string Name,
    string Description,
    int Score,
    List<PatternString> Strings,
    string Condition = "any",
    bool Definitive = false);

internal sealed record PatternRuleFile(List<PatternRule>? Rules);

/// <summary>
/// Moteur de règles de contenu (sous-ensemble de YARA, 100 % managé) : recherche de chaînes et de motifs
/// hexadécimaux dans les premiers <see cref="MaxScanBytes"/> octets du fichier.
/// Les règles sensibles sont stockées en hexadécimal dans <c>rules.json</c>, pour que la base elle-même
/// ne soit pas prise pour un malware par un autre antivirus.
/// </summary>
public sealed class PatternRuleEngine : IDetectionEngine
{
    public const int MaxScanBytes = 32 * 1024 * 1024;
    private const int MaxPatternLength = 1024;

    private readonly List<CompiledRule> _rules = [];
    private readonly bool _needsLower;

    public string Name => "Règles";

    public int Count => _rules.Count;

    public PatternRuleEngine(string rulesPath) : this(LoadRules(rulesPath)) { }

    public PatternRuleEngine(IEnumerable<PatternRule> rules)
    {
        foreach (var rule in rules)
        {
            var compiled = Compile(rule);
            if (compiled is not null) _rules.Add(compiled);
        }
        _needsLower = _rules.Any(r => r.Patterns.Any(p => p.NoCase));
    }

    private static IEnumerable<PatternRule> LoadRules(string path)
    {
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var file = JsonSerializer.Deserialize<PatternRuleFile>(File.ReadAllText(path), options);
        return file?.Rules ?? [];
    }

    public async Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default)
    {
        if (_rules.Count == 0 || report.SizeBytes == 0) return [];

        byte[] buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(report.SizeBytes, MaxScanBytes));
        try
        {
            int length;
            await using (var stream = new FileStream(report.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                             bufferSize: 81920, useAsync: true))
            {
                length = await stream.ReadAtLeastAsync(buffer.AsMemory(0, Math.Min(buffer.Length, MaxScanBytes)),
                    Math.Min(buffer.Length, MaxScanBytes), throwOnEndOfStream: false, ct);
            }
            return Evaluate(buffer.AsSpan(0, length), ct);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Évalue toutes les règles sur un contenu déjà chargé (utile pour la mémoire ou les tests).</summary>
    public IReadOnlyList<Indicator> Evaluate(ReadOnlySpan<byte> content, CancellationToken ct = default)
    {
        byte[]? lowered = null;
        if (_needsLower)
        {
            lowered = ArrayPool<byte>.Shared.Rent(Math.Max(content.Length, 1));
            for (int i = 0; i < content.Length; i++)
            {
                byte b = content[i];
                lowered[i] = b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b | 0x20) : b;
            }
        }

        try
        {
            var indicators = new List<Indicator>();
            ReadOnlySpan<byte> lower = lowered is null ? default : lowered.AsSpan(0, content.Length);
            foreach (var rule in _rules)
            {
                ct.ThrowIfCancellationRequested();
                int found = 0;
                foreach (var p in rule.Patterns)
                {
                    if (p.Matches(p.NoCase ? lower : content)) found++;
                    if (found >= rule.MinMatches) break;
                }
                if (found >= rule.MinMatches)
                    indicators.Add(new Indicator(Name, $"Règle « {rule.Name} » : {rule.Description}", rule.Score, rule.Definitive));
            }
            return indicators;
        }
        finally
        {
            if (lowered is not null) ArrayPool<byte>.Shared.Return(lowered);
        }
    }

    // ---------- Compilation ----------

    private sealed record CompiledRule(string Name, string Description, int Score, bool Definitive, int MinMatches, List<CompiledPattern> Patterns);

    private static CompiledRule? Compile(PatternRule rule)
    {
        if (string.IsNullOrWhiteSpace(rule.Name) || rule.Strings is null || rule.Strings.Count == 0) return null;

        var patterns = new List<CompiledPattern>();
        foreach (var s in rule.Strings)
        {
            var p = CompiledPattern.From(s);
            if (p is not null) patterns.Add(p);
        }
        if (patterns.Count == 0) return null;

        int min = (rule.Condition ?? "any").Trim().ToLowerInvariant() switch
        {
            "any" => 1,
            "all" => patterns.Count,
            var n when int.TryParse(n, NumberStyles.None, CultureInfo.InvariantCulture, out int v) => Math.Clamp(v, 1, patterns.Count),
            _ => 1
        };

        return new CompiledRule(rule.Name, rule.Description ?? "", Math.Clamp(rule.Score, 0, 100), rule.Definitive, min, patterns);
    }

    private sealed class CompiledPattern
    {
        private readonly byte[] _bytes;
        private readonly bool[]? _wildcard; // null = motif exact (recherche vectorisée)
        private readonly int _anchor;       // premier octet non joker, sert d'ancre de recherche

        public bool NoCase { get; }

        private CompiledPattern(byte[] bytes, bool[]? wildcard, bool noCase)
        {
            _bytes = bytes;
            _wildcard = wildcard;
            NoCase = noCase;
            _anchor = wildcard is null ? 0 : Array.IndexOf(wildcard, false);
        }

        public static CompiledPattern? From(PatternString s)
        {
            if (!string.IsNullOrEmpty(s.Text))
            {
                string text = s.NoCase ? s.Text.ToLowerInvariant() : s.Text;
                byte[] bytes = s.Wide ? Encoding.Unicode.GetBytes(text) : Encoding.Latin1.GetBytes(text);
                return bytes.Length is 0 or > MaxPatternLength ? null : new CompiledPattern(bytes, null, s.NoCase);
            }

            if (!string.IsNullOrEmpty(s.Hex))
            {
                string hex = new(s.Hex.Where(c => !char.IsWhiteSpace(c)).ToArray());
                if (hex.Length == 0 || hex.Length % 2 != 0 || hex.Length / 2 > MaxPatternLength) return null;

                var bytes = new byte[hex.Length / 2];
                var wild = new bool[bytes.Length];
                for (int i = 0; i < bytes.Length; i++)
                {
                    string pair = hex.Substring(i * 2, 2);
                    if (pair == "??") { wild[i] = true; continue; }
                    if (!byte.TryParse(pair, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i])) return null;
                }
                if (wild.All(w => w)) return null; // motif uniquement composé de jokers : refusé

                if (s.NoCase)
                    for (int i = 0; i < bytes.Length; i++)
                        if (bytes[i] is >= (byte)'A' and <= (byte)'Z') bytes[i] |= 0x20;

                return new CompiledPattern(bytes, wild.Any(w => w) ? wild : null, s.NoCase);
            }

            return null;
        }

        public bool Matches(ReadOnlySpan<byte> data)
        {
            if (_wildcard is null) return data.IndexOf(_bytes) >= 0;

            byte anchor = _bytes[_anchor];
            int offset = 0;
            while (offset <= data.Length - _bytes.Length)
            {
                int idx = data[(offset + _anchor)..(data.Length - _bytes.Length + _anchor + 1)].IndexOf(anchor);
                if (idx < 0) return false;
                int start = offset + idx;
                if (MatchAt(data, start)) return true;
                offset = start + 1;
            }
            return false;
        }

        private bool MatchAt(ReadOnlySpan<byte> data, int start)
        {
            for (int i = 0; i < _bytes.Length; i++)
                if (!_wildcard![i] && data[start + i] != _bytes[i]) return false;
            return true;
        }
    }
}
