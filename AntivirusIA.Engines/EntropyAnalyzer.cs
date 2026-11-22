using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Engines;

public sealed class EntropyAnalyzer : IDetectionEngine
{
    private const double Seuil = 7.5;

    public string Name => "Entropie";

    public async Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default)
    {
        var indicators = new List<Indicator>();

        string ext = Path.GetExtension(report.FileName);
        if (!FileTypes.Executables.Contains(ext) || report.SizeBytes < 1024)
            return indicators;

        double entropie = await ComputeEntropyAsync(report.FullPath, ct);
        if (entropie >= Seuil)
        {
            indicators.Add(new Indicator(Name,
                $"Entropie très élevée ({entropie:F2}/8) : programme probablement packé ou chiffré", 15));
        }

        return indicators;
    }

    // Entropie de Shannon, de 0 (contenu répétitif) à 8 (contenu aléatoire)
    public static async Task<double> ComputeEntropyAsync(string path, CancellationToken ct = default)
    {
        var compteurs = new long[256];
        long total = 0;

        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            bufferSize: 81920, useAsync: true);

        var tampon = new byte[81920];
        int lus;
        while ((lus = await stream.ReadAsync(tampon, ct)) > 0)
        {
            for (int i = 0; i < lus; i++)
                compteurs[tampon[i]]++;
            total += lus;
        }

        if (total == 0) return 0;

        double entropie = 0;
        foreach (long c in compteurs)
        {
            if (c == 0) continue;
            double p = (double)c / total;
            entropie -= p * Math.Log2(p);
        }
        return entropie;
    }
}