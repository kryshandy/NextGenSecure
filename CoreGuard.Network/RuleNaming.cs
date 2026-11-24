namespace CoreGuard.Network;

/// <summary>Construction pure (testable) des noms de règles du pare-feu CoreGuard.</summary>
public static class RuleNaming
{
    /// <summary>Préfixe commun : permet de ne jamais toucher aux règles qui ne sont pas les nôtres.</summary>
    public const string Prefix = "CoreGuard - ";

    /// <summary>Nom de la règle du kill switch.</summary>
    public const string KillSwitchRuleName = Prefix + "KillSwitch";

    /// <summary>Normalise un nom : ajoute le préfixe, retire les caractères de contrôle et le séparateur '|'.</summary>
    public static string ForRule(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var clean = new string(name.Where(c => !char.IsControl(c) && c != '|').ToArray()).Trim();
        if (clean.Length == 0) throw new ArgumentException("Nom de règle invalide.", nameof(name));
        return clean.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) ? clean : Prefix + clean;
    }

    /// <summary>Nom de règle pour un blocage par application.</summary>
    public static string ForApplication(string appPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appPath);
        return ForRule("Block " + Path.GetFileName(appPath));
    }

    /// <summary>Nom de règle pour un blocage par port.</summary>
    public static string ForPort(int port, string protocol)
        => ForRule($"Block {NormalizeProtocol(protocol)} port {ValidatePort(port)}");

    /// <summary>Valide qu'un port est dans 1-65535.</summary>
    public static int ValidatePort(int port)
        => port is >= 1 and <= 65535 ? port : throw new ArgumentOutOfRangeException(nameof(port), "Port hors plage 1-65535.");

    /// <summary>Numéro de protocole IANA : TCP=6, UDP=17.</summary>
    public static int ProtocolNumber(string protocol) => NormalizeProtocol(protocol) switch
    {
        "TCP" => 6,
        "UDP" => 17,
        _ => throw new ArgumentException("Protocole non supporté (TCP/UDP).", nameof(protocol))
    };

    /// <summary>Met le protocole en majuscules.</summary>
    public static string NormalizeProtocol(string protocol)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protocol);
        return protocol.Trim().ToUpperInvariant();
    }
}
