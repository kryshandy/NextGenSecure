using System.Security.Cryptography;

namespace AntivirusIA.Engines;

public static class FileHasher
{
    public static async Task<string> ComputeSha256Async(string path, CancellationToken ct = default)
    {
        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            bufferSize: 81920, useAsync: true);

        byte[] hash = await SHA256.HashDataAsync(stream, ct);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}