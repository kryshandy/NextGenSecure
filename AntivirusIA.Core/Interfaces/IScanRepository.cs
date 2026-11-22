using AntivirusIA.Core.Models;

namespace AntivirusIA.Core.Interfaces;

public interface IScanRepository
{
    Task SaveScanAsync(ScanResult result, CancellationToken ct = default);
    Task<IReadOnlyList<ScanRecord>> GetHistoryAsync(int limite = 100, CancellationToken ct = default);
    Task<ScanRecord?> GetLastScanByHashAsync(string sha256, CancellationToken ct = default);

    Task AddToWhitelistAsync(string sha256, string cheminOrigine, CancellationToken ct = default);
    Task RemoveFromWhitelistAsync(string sha256, CancellationToken ct = default);
    Task<bool> IsWhitelistedAsync(string sha256, CancellationToken ct = default);
}