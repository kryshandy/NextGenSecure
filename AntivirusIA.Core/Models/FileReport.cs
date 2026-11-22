namespace AntivirusIA.Core.Models;

public sealed class FileReport
{
    public required string FullPath { get; init; }
    public string FileName => Path.GetFileName(FullPath);
    public long SizeBytes { get; init; }
    public string? Sha256 { get; set; }
}