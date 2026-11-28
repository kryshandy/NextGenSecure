using System.Runtime.InteropServices;
using System.Security.Principal;

namespace CoreGuard.Network;

/// <summary>
/// Pilote le pare-feu Windows via COM (HNetCfg.FwPolicy2 / INetFwPolicy2) en liaison tardive
/// (<c>dynamic</c>) : aucune assembly d'interop n'est requise.
/// Toutes les règles portent le préfixe <see cref="RuleNaming.Prefix"/>.
///
/// PHASE 2 (ébauche) : un blocage par PID, sans passer par un chemin d'exécutable, est possible
/// avec Windows Filtering Platform bas niveau (fwpuclnt.dll : FwpmEngineOpen0, FwpmFilterAdd0 avec une
/// condition FWPM_CONDITION_ALE_APP_ID ou FWPM_CONDITION_IP_REMOTE_PORT sur la couche
/// FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6). Cela exige un provider/sublayer dédié et un service élevé ;
/// hors périmètre de la Phase 1 user-mode.
/// </summary>
public sealed class WindowsFirewall : INetworkGuard
{
    private const int ActionBlock = 0;     // NET_FW_ACTION_BLOCK
    private const int DirOut = 2;          // NET_FW_RULE_DIR_OUT
    private const int ProfilesAll = 0x7FFFFFFF;

    /// <inheritdoc />
    public bool CanManageFirewall => IsAdministrator();

    /// <inheritdoc />
    public bool IsKillSwitchActive
    {
        get
        {
            try
            {
                dynamic policy = CreatePolicy();
                foreach (dynamic rule in policy.Rules)
                    if (string.Equals((string)rule.Name, RuleNaming.KillSwitchRuleName, StringComparison.OrdinalIgnoreCase))
                        return (bool)rule.Enabled;
            }
            catch { /* lecture impossible : considéré inactif */ }
            return false;
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<Connection> GetConnections() => PortInspector.GetConnections();

    /// <inheritdoc />
    public void BlockApplication(string ruleName, string appPath) => BlockOutbound(ruleName, appPath);

    /// <summary>Ajoute une règle de blocage sortant pour un exécutable.</summary>
    public void BlockOutbound(string ruleName, string appPath)
    {
        var name = RuleNaming.ForRule(ruleName);
        ArgumentException.ThrowIfNullOrWhiteSpace(appPath);
        AddRule(name, rule => rule.ApplicationName = appPath);
    }

    /// <inheritdoc />
    public void BlockPort(string ruleName, int port, string protocol = "TCP")
    {
        var name = RuleNaming.ForRule(ruleName);
        int proto = RuleNaming.ProtocolNumber(protocol);
        RuleNaming.ValidatePort(port);
        AddRule(name, rule =>
        {
            rule.Protocol = proto;
            rule.RemotePorts = port.ToString();
        });
    }

    /// <summary>
    /// Autorise les connexions ENTRANTES sur un port TCP, uniquement depuis le sous-réseau local (Wi-Fi, point
    /// d'accès mobile du PC) : jamais depuis Internet. Utilisé par le contrôle à distance par téléphone.
    /// </summary>
    public void AllowInboundPortFromLocalSubnet(string ruleName, int port)
    {
        var name = RuleNaming.ForRule(ruleName);
        RuleNaming.ValidatePort(port);
        RemoveRule(ruleName);
        AddRule(name, rule =>
        {
            rule.Direction = 1;          // NET_FW_RULE_DIR_IN
            rule.Action = 1;             // NET_FW_ACTION_ALLOW
            rule.Protocol = 6;           // TCP
            rule.LocalPorts = port.ToString();
            rule.RemoteAddresses = "LocalSubnet";
        });
    }

    /// <inheritdoc />
    public bool RemoveRule(string ruleName)
    {
        var name = RuleNaming.ForRule(ruleName);
        return Guarded(() =>
        {
            dynamic policy = CreatePolicy();
            bool existed = false;
            foreach (dynamic r in policy.Rules)
                if (string.Equals((string)r.Name, name, StringComparison.OrdinalIgnoreCase)) { existed = true; break; }
            if (!existed) return false;
            policy.Rules.Remove(name);
            return true;
        });
    }

    /// <summary>
    /// Kill switch : règle sortante bloquant tout le trafic vers toutes les adresses.
    /// Désactivation = suppression de la règle.
    /// </summary>
    public void KillSwitch(bool on)
    {
        if (!on) { RemoveRule(RuleNaming.KillSwitchRuleName); return; }
        if (IsKillSwitchActive) return;
        AddRule(RuleNaming.KillSwitchRuleName, rule => { rule.RemoteAddresses = "*"; });
    }

    private void AddRule(string name, Action<dynamic> configure)
    {
        Guarded(() =>
        {
            dynamic policy = CreatePolicy();
            Type ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
                ?? throw new NetworkGuardException("Composant COM HNetCfg.FWRule introuvable.");
            dynamic rule = Activator.CreateInstance(ruleType)!;
            rule.Name = name;
            rule.Description = "Règle gérée par CoreGuard";
            rule.Direction = DirOut;
            rule.Action = ActionBlock;
            rule.Enabled = true;
            rule.Profiles = ProfilesAll;
            configure(rule);
            policy.Rules.Add(rule);
            return true;
        });
    }

    private static dynamic CreatePolicy()
    {
        var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new NetworkGuardException("Pare-feu Windows (HNetCfg.FwPolicy2) indisponible sur ce système.");
        return Activator.CreateInstance(t)!;
    }

    // Vérifie les droits puis convertit les erreurs COM en exception explicite.
    private static T Guarded<T>(Func<T> action)
    {
        if (!IsAdministrator())
            throw new NetworkGuardException("Droits administrateur requis pour modifier le pare-feu Windows.");
        try { return action(); }
        catch (NetworkGuardException) { throw; }
        catch (UnauthorizedAccessException ex)
        {
            throw new NetworkGuardException("Accès refusé au pare-feu Windows : exécutez CoreGuard en administrateur.", ex);
        }
        catch (COMException ex)
        {
            throw new NetworkGuardException($"Erreur du pare-feu Windows (0x{ex.HResult:X8}) : {ex.Message}", ex);
        }
        catch (Exception ex) when (ex is Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
        {
            throw new NetworkGuardException("Interface du pare-feu Windows inattendue : " + ex.Message, ex);
        }
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
