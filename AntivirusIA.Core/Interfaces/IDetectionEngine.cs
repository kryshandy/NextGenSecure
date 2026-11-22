using AntivirusIA.Core.Models;

namespace AntivirusIA.Core.Interfaces;

// Contrat que tous nos moteurs d'analyse devront respecter
public interface IDetectionEngine
{
    string Name { get; }

    Task<IReadOnlyList<Indicator>> AnalyzeAsync(FileReport report, CancellationToken ct = default);
}