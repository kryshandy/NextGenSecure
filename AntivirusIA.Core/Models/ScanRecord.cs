namespace AntivirusIA.Core.Models;

// Une ligne de l'historique des analyses
public sealed record ScanRecord(
    long Id,
    DateTime DateUtc,
    string Path,
    string? Sha256,
    int Score,
    Verdict Verdict,
    string Details);