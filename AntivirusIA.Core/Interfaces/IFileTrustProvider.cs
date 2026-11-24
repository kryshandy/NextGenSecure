using AntivirusIA.Core.Models;

namespace AntivirusIA.Core.Interfaces;

// Indique si un fichier porte une signature numérique valide (Authenticode sous Windows)
public interface IFileTrustProvider
{
    Task<FileTrust> EvaluateAsync(string path, CancellationToken ct = default);
}
