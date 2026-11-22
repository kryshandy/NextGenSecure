namespace AntivirusIA.Core.Models;

// Un indice détecté sur un fichier et les points de risque qu'il ajoute
public sealed record Indicator(string Source, string Description, int Points);