using AntivirusIA.Core.Models;

namespace AntivirusIA.Core.Interfaces;

public interface IQuarantineService
{
    Task<QuarantineEntry> QuarantineAsync(string cheminFichier, string raison, CancellationToken ct = default);
    Task RestoreAsync(Guid id, CancellationToken ct = default);
    Task DeleteAsync(Guid id, CancellationToken ct = default);
    IReadOnlyList<QuarantineEntry> List();
}