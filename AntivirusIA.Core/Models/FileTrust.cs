namespace AntivirusIA.Core.Models;

// Résultat de la vérification de signature numérique d'un fichier.
// Signé et valide ne veut PAS dire sain (certificats volés) : seules les heuristiques sont atténuées.
public sealed record FileTrust(bool IsSigned, bool IsValid, string? Publisher = null)
{
    public static readonly FileTrust Unsigned = new(false, false);

    public bool IsTrusted => IsSigned && IsValid;
}
