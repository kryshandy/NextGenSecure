namespace AntivirusIA.Core.Models;

// Un indice détecté sur un fichier et les points de risque qu'il ajoute.
// Definitive = preuve forte (hash connu, règle de contenu caractéristique) : jamais atténuée par la signature numérique.
// Les autres indices sont des heuristiques, atténuées quand le fichier porte une signature Authenticode valide.
public sealed record Indicator(string Source, string Description, int Points, bool Definitive = false);
