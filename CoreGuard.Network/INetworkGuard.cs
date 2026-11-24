namespace CoreGuard.Network;

/// <summary>
/// Façade réseau exposée à la couche service : inspection des ports
/// et pilotage du pare-feu applicatif / kill switch.
/// </summary>
public interface INetworkGuard
{
    /// <summary>Liste les connexions TCP/UDP (IPv4 + IPv6) avec le processus propriétaire.</summary>
    IReadOnlyList<Connection> GetConnections();

    /// <summary>Bloque le trafic sortant d'un exécutable. Lève <see cref="NetworkGuardException"/> si droits insuffisants.</summary>
    void BlockApplication(string ruleName, string appPath);

    /// <summary>Bloque le trafic sortant vers un port distant donné.</summary>
    void BlockPort(string ruleName, int port, string protocol = "TCP");

    /// <summary>Supprime une règle posée par CoreGuard. Retourne false si elle n'existe pas.</summary>
    bool RemoveRule(string ruleName);

    /// <summary>Active/désactive le kill switch (blocage de tout le trafic sortant non essentiel).</summary>
    void KillSwitch(bool on);

    /// <summary>Indique si le kill switch est actuellement actif.</summary>
    bool IsKillSwitchActive { get; }

    /// <summary>Vrai si le processus courant peut modifier le pare-feu (administrateur).</summary>
    bool CanManageFirewall { get; }
}
