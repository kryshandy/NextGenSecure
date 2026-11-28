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
public static class EmberFeatures
{
    public const int Count = 616;
    private const int Window = 2048;
    private const int Step = 1024;






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

    // Un seul passage sur les octets, sémantique identique aux expressions régulières d'EMBER :
    // [\x20-\x7f]{5,} (suites maximales), « c:\ » et « http(s):// » insensibles à la casse, « HKEY_ » et « MZ » ;
    // chaque motif est compté sans chevauchement, de gauche à droite, indépendamment des autres (re.findall).
    private static void Strings(ReadOnlySpan<byte> bytes, Span<float> output)
    {
        Span<long> dist = stackalloc long[96];
        dist.Clear();
        long printables = 0, count = 0;
        int runStart = -1;
        int paths = 0, urls = 0, registry = 0, mz = 0;
        int nextPaths = 0, nextUrls = 0, nextRegistry = 0, nextMz = 0;
        int n = bytes.Length;

        for (int i = 0; i <= n; i++)
        {
            bool printable = i < n && bytes[i] >= 0x20 && bytes[i] <= 0x7f;
            if (printable)
            {
                if (runStart < 0) runStart = i;
            }
            else if (runStart >= 0)
            {
                int length = i - runStart;
                if (length >= 5)
                {
                    count++;
                    printables += length;
                    foreach (byte c in bytes.Slice(runStart, length)) dist[c - 0x20]++;
                }
                runStart = -1;
            }
            if (i == n) break;

            byte b = bytes[i];
            int lower = b | 0x20;
            if (lower == 'c' && i >= nextPaths && i + 2 < n && bytes[i + 1] == ':' && bytes[i + 2] == '\\')
            {
                paths++;
                nextPaths = i + 3;
            }
            if (lower == 'h' && i >= nextUrls && i + 6 < n && (bytes[i + 1] | 0x20) == 't' && (bytes[i + 2] | 0x20) == 't' && (bytes[i + 3] | 0x20) == 'p')
            {
                int j = i + 4;
                if ((bytes[j] | 0x20) == 's') j++;
                if (j + 2 < n && bytes[j] == ':' && bytes[j + 1] == '/' && bytes[j + 2] == '/')
                {
                    urls++;
                    nextUrls = j + 3;
                }
            }
            if (b == 'H' && i >= nextRegistry && i + 4 < n && bytes[i + 1] == 'K' && bytes[i + 2] == 'E' && bytes[i + 3] == 'Y' && bytes[i + 4] == '_')
            {
                registry++;
                nextRegistry = i + 5;
            }
            if (b == 'M' && i >= nextMz && i + 1 < n && bytes[i + 1] == 'Z')
            {
                mz++;
                nextMz = i + 2;
            }
        }

        double avLength = count > 0 ? (double)printables / count : 0;
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
        output[0] = count;
        output[1] = (float)avLength;
        output[2] = printables;
        for (int i = 0; i < 96; i++) output[3 + i] = (float)(dist[i] / divisor);
        output[99] = entropy;
        output[100] = paths;
        output[101] = urls;
        output[102] = registry;
        output[103] = mz;
    }
}
