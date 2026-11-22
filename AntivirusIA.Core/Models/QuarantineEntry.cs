namespace AntivirusIA.Core.Models;

public sealed record QuarantineEntry(
    Guid Id,
    string OriginalPath,
    string Reason,
    DateTime DateUtc,
    long SizeBytes);