using System.Text.RegularExpressions;

namespace CoreGuard.Privacy;

public enum CryptoKind { None, Bitcoin, Ethereum }

/// <summary>Méthodes PURES de détection (sans effet de bord) pour le presse-papiers.</summary>
public static partial class ClipboardAnalysis
{
    /// <summary>Délai en dessous duquel une modification du presse-papiers est jugée suspecte.</summary>
    public static readonly TimeSpan SuspiciousDelay = TimeSpan.FromMilliseconds(200);

    [GeneratedRegex(@"^(bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")]
    private static partial Regex BtcRegex();

    [GeneratedRegex(@"^0x[0-9a-fA-F]{40}$")]
    private static partial Regex EthRegex();

    [GeneratedRegex(@"\b(sk-[A-Za-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9\-]{10,})")]
    private static partial Regex ApiKeyRegex();

    /// <summary>Type d'adresse crypto (BTC/ETH) du texte, ou None.</summary>
    public static CryptoKind DetectCryptoAddress(string? text)
    {
        var t = text?.Trim();
        if (string.IsNullOrEmpty(t)) return CryptoKind.None;
        if (EthRegex().IsMatch(t)) return CryptoKind.Ethereum;
        if (BtcRegex().IsMatch(t)) return CryptoKind.Bitcoin;
        return CryptoKind.None;
    }

    /// <summary>Vrai si les deux contenus sont des adresses crypto DIFFÉRENTES (remplacement par un clipper).</summary>
    public static bool IsAddressSwap(string? before, string? after)
    {
        var a = DetectCryptoAddress(before);
        var b = DetectCryptoAddress(after);
        return a != CryptoKind.None && b != CryptoKind.None
               && !string.Equals(before!.Trim(), after!.Trim(), StringComparison.Ordinal);
    }

    /// <summary>
    /// Vrai si la modification est suspecte : très rapprochée de la précédente (&lt; 200 ms)
    /// alors que le processus au premier plan n'est pas celui qui détient le presse-papiers.
    /// </summary>
    public static bool IsSuspiciousModification(TimeSpan sinceLastCopy, bool foregroundOwnsClipboard) =>
        sinceLastCopy >= TimeSpan.Zero && sinceLastCopy < SuspiciousDelay && !foregroundOwnsClipboard;

    /// <summary>Vrai si le texte ressemble à un secret : clé API, clé privée, carte bancaire, mot de passe fort.</summary>
    public static bool IsSecret(string? text)
    {
        var t = text?.Trim();
        if (string.IsNullOrEmpty(t) || t.Length > 4096) return false;
        if (ApiKeyRegex().IsMatch(t)) return true;
        if (t.Contains("-----BEGIN ", StringComparison.Ordinal) && t.Contains("PRIVATE KEY", StringComparison.Ordinal)) return true;
        return IsCreditCard(t) || IsStrongPassword(t);
    }

    /// <summary>Carte bancaire : 13 à 19 chiffres (espaces/tirets tolérés) validés par Luhn.</summary>
    public static bool IsCreditCard(string text)
    {
        var digits = new List<int>();
        foreach (var c in text)
        {
            if (char.IsAsciiDigit(c)) digits.Add(c - '0');
            else if (c is not (' ' or '-')) return false;
        }
        if (digits.Count is < 13 or > 19) return false;
        int sum = 0; bool dbl = false;
        for (int i = digits.Count - 1; i >= 0; i--)
        {
            int d = digits[i];
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d; dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    /// <summary>Mot de passe fort : un seul mot de 12 à 64 car., sans espace, 4 classes de caractères, pas une adresse.</summary>
    public static bool IsStrongPassword(string text)
    {
        if (text.Length is < 12 or > 64 || text.Any(char.IsWhiteSpace)) return false;
        if (DetectCryptoAddress(text) != CryptoKind.None) return false;
        int classes = (text.Any(char.IsAsciiLetterLower) ? 1 : 0) + (text.Any(char.IsAsciiLetterUpper) ? 1 : 0)
                    + (text.Any(char.IsAsciiDigit) ? 1 : 0) + (text.Any(c => !char.IsAsciiLetterOrDigit(c)) ? 1 : 0);
        return classes == 4;
    }
}
