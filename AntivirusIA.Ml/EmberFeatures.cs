using System.Text.RegularExpressions;

namespace AntivirusIA.Ml;

/// <summary>
/// Sous-ensemble des caractéristiques EMBER 2018 (Anderson &amp; Roth, 2018), recalculé À L'IDENTIQUE de
/// l'implémentation de référence (ember/features.py) : ce sont les colonnes 0 à 615 du vecteur EMBER v2.
/// <list type="bullet">
/// <item>ByteHistogram (256) : fréquence de chaque octet ;</item>
/// <item>ByteEntropyHistogram (256) : histogramme conjoint (entropie locale × quartet haut) sur des fenêtres de
///       2048 octets avancant de 1024 ;</item>
/// <item>StringExtractor (104) : chaînes imprimables de 5 caractères ou plus, distribution des caractères,
///       entropie, motifs « C:\ », « http(s):// », « HKEY_ », « MZ ».</item>
/// </list>
/// Ces trois groupes se calculent sur les octets bruts, sans analyseur PE : aucune divergence possible avec les
/// données d'entraînement (les groupes « en-tête / sections / imports » d'EMBER dépendent de LIEF).
/// </summary>
public static partial class EmberFeatures
{
    public const int Count = 616;
    private const int Window = 2048;
    private const int Step = 1024;

    [GeneratedRegex("[\\x20-\\x7f]{5,}", RegexOptions.CultureInvariant)]
    private static partial Regex AllStrings();

    [GeneratedRegex("c:\\\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Paths();

    [GeneratedRegex("https?://", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Urls();

    [GeneratedRegex("HKEY_", RegexOptions.CultureInvariant)]
    private static partial Regex Registry();

    [GeneratedRegex("MZ", RegexOptions.CultureInvariant)]
    private static partial Regex Mz();

    public static float[] Extract(ReadOnlySpan<byte> bytes)
    {
        var v = new float[Count];
        ByteHistogram(bytes, v.AsSpan(0, 256));
        ByteEntropyHistogram(bytes, v.AsSpan(256, 256));
        Strings(bytes, v.AsSpan(512, 104));
        return v;
    }

    // np.bincount(bytez, minlength=256) / total
    private static void ByteHistogram(ReadOnlySpan<byte> bytes, Span<float> output)
    {
        var counts = new long[256];
        foreach (byte b in bytes) counts[b]++;
        double total = bytes.Length;
        for (int i = 0; i < 256; i++) output[i] = total > 0 ? (float)(counts[i] / total) : 0f;
    }

    private static void ByteEntropyHistogram(ReadOnlySpan<byte> bytes, Span<float> output)
    {
        var matrix = new long[16 * 16];
        if (bytes.Length < Window)
        {
            AddBlock(bytes, matrix);
        }
        else
        {
            // Fenêtres glissantes de 2048 octets, une sur 1024 (as_strided(...)[::step])
            for (int start = 0; start + Window <= bytes.Length; start += Step)
                AddBlock(bytes.Slice(start, Window), matrix);
        }
        double sum = 0;
        foreach (long c in matrix) sum += c;
        for (int i = 0; i < 256; i++) output[i] = sum > 0 ? (float)(matrix[i] / sum) : 0f;
    }

    private static void AddBlock(ReadOnlySpan<byte> block, long[] matrix)
    {
        Span<int> c = stackalloc int[16];
        foreach (byte b in block) c[b >> 4]++;
        // p = c / window (même pour un bloc plus court, comme l'implémentation de référence), calcul en float32 (NumPy)
        float h = 0;
        for (int i = 0; i < 16; i++)
        {
            if (c[i] == 0) continue;
            float p = (float)c[i] / Window;
            h += -p * MathF.Log2(p);
        }
        h *= 2; // 16 classes (4 bits) au lieu de 256 : information divisée par deux
        int bin = (int)(h * 2);
        if (bin >= 16) bin = 15;
        for (int i = 0; i < 16; i++) matrix[bin * 16 + i] += c[i];
    }

    private static void Strings(ReadOnlySpan<byte> bytes, Span<float> output)
    {
        string latin = Latin1(bytes); // 1 octet = 1 caractère : les expressions régulières travaillent sur les octets
        var matches = AllStrings().Matches(latin);
        var dist = new long[96];
        long printables = 0, totalLength = 0;
        foreach (Match m in matches)
        {
            totalLength += m.Length;
            foreach (char ch in m.ValueSpan) { dist[ch - 0x20]++; printables++; }
        }
        double avLength = matches.Count > 0 ? (double)totalLength / matches.Count : 0;
        float entropy = 0;
        if (printables > 0)
        {
            for (int i = 0; i < 96; i++)
            {
                if (dist[i] == 0) continue;
                float p = (float)dist[i] / printables;
                entropy += -p * MathF.Log2(p);
            }
        }
        double divisor = printables > 0 ? printables : 1.0;
        output[0] = matches.Count;
        output[1] = (float)avLength;
        output[2] = printables;
        for (int i = 0; i < 96; i++) output[3 + i] = (float)(dist[i] / divisor);
        output[99] = entropy;
        output[100] = Paths().Count(latin);
        output[101] = Urls().Count(latin);
        output[102] = Registry().Count(latin);
        output[103] = Mz().Count(latin);
    }

    private static string Latin1(ReadOnlySpan<byte> bytes) => System.Text.Encoding.Latin1.GetString(bytes);
}
