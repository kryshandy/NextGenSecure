using AntivirusIA.Core.Interfaces;
using AntivirusIA.Core.Models;

namespace AntivirusIA.Engines;

public sealed class HeuristicEngine : IDetectionEngine
{
    private static readonly string[] DossiersSuspects =
        { @"\temp\", @"\appdata\", @"\programdata\", @"\users\public\" };

    public string Name => "Heuristiques";

    public Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default)
    {
        var indicators = new List<Indicator>();
        string nom = report.FileName;
        string ext = Path.GetExtension(nom);
        bool executable = FileTypes.Executables.Contains(ext) || FileTypes.Scripts.Contains(ext);

        // Caractère invisible qui inverse le texte : "photo<RLO>gpj.exe" s'affiche "photoexe.jpg"
        if (nom.Contains('\u202E'))
            indicators.Add(new Indicator(Name,
                "Caractère d'inversion de texte (RLO) dans le nom : extension truquée", 30));

        if (executable)
        {
            string extInterne = Path.GetExtension(Path.GetFileNameWithoutExtension(nom));
            if (FileTypes.Documents.Contains(extInterne))
                indicators.Add(new Indicator(Name,
                    $"Double extension ({extInterne}{ext}) : un programme qui se fait passer pour un document", 25));

            string dossier = (Path.GetDirectoryName(report.FullPath) ?? "") + "\\";
            if (DossiersSuspects.Any(d => dossier.Contains(d, StringComparison.OrdinalIgnoreCase)))
                indicators.Add(new Indicator(Name,
                    "Programme situé dans un dossier temporaire ou de données utilisateur", 10));

            if (File.Exists(report.FullPath) &&
                File.GetAttributes(report.FullPath).HasFlag(FileAttributes.Hidden))
                indicators.Add(new Indicator(Name, "Programme avec l'attribut « caché »", 10));
        }

        return Task.FromResult<IReadOnlyList<Indicator>>(indicators);
    }
}