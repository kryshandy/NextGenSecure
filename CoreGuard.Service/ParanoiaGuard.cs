using System.Runtime.Versioning;
using System.Text.Json;
using AntivirusIA.Core.Interfaces;
using CoreGuard.Ipc;
using CoreGuard.Network;
using CoreGuard.Behavior;

namespace CoreGuard.Service;

/// <summary>État persistant du Mode Paranoïa (ré-appliqué après un redémarrage).</summary>
public sealed record ParanoiaState(bool Enabled, int? OriginalUsbStart, DateTime? SinceUtc);

/// <summary>
/// Mode Paranoïa réel, appliqué par le service (SYSTEM) :
/// - clés et disques USB refusés (pilote USBSTOR désactivé, valeur d'origine mémorisée) ;
/// - WFP natif en session dynamique : entrées refusées (hors trafic local) et sortie coupée pour les outils système
///   détournés (mshta, certutil, bitsadmin…) — si le service s'arrête, Windows retire ces filtres de lui-même ;
/// - tout exécutable non signé lancé depuis un dossier de l'utilisateur est arrêté dès son démarrage (ETW).
/// L'activation est libre (elle ne fait que renforcer) ; la désactivation exige le mot de passe de protection.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ParanoiaGuard(
    IKernelActionProvider actions,
    ILockdownBackend usb,
    Func<bool> lockdownEngaged,
    Action<string, string, string, string> publish,
    ILogger logger,
    string statePath,
    Func<ushort[]>? allowedInboundPorts = null) : IDisposable
{
    private const int UsbDisabled = 4;
    private readonly object _gate = new();
    private readonly AntivirusIA.Engines.AuthenticodeVerifier _authenticode = new();
    private ParanoiaState _state = Load(statePath) ?? new ParanoiaState(false, null, null);
    private WfpFirewall? _wfp;
    private UserDirExecutionGuard? _exec;
    private string _firewallText = "";

    public bool Enabled { get { lock (_gate) return _state.Enabled; } }

    public string StatusText
    {
        get
        {
            lock (_gate)
            {
                if (!_state.Enabled) return "Désactivé";
                return $"Actif depuis {_state.SinceUtc?.ToLocalTime():HH:mm} : USB bloqué, {_firewallText}, " +
                       $"exécution non signée depuis les dossiers utilisateur bloquée ({_exec?.BlockedCount ?? 0} arrêt(s))";
            }
        }
    }

    /// <summary>Au démarrage du service : ré-applique le mode s'il était actif avant un redémarrage.</summary>
    public void Reassert()
    {
        lock (_gate)
        {
            if (_state.Enabled) ApplyLocked();
        }
    }

    public StopResult Enable()
    {
        lock (_gate)
        {
            if (_state.Enabled) return new StopResult(true, "Mode Paranoïa déjà actif.");
            int? original = usb.GetUsbStorageStart();
            _state = new ParanoiaState(true, original == UsbDisabled ? _state.OriginalUsbStart ?? 3 : original, DateTime.UtcNow);
            Save(_state);
            ApplyLocked();
        }
        publish("Warning", "Paranoïa", "Mode Paranoïa activé", StatusText);
        return new StopResult(true, "Mode Paranoïa activé.");
    }

    /// <summary>Appelé après vérification du mot de passe de protection.</summary>
    public StopResult Disable()
    {
        lock (_gate)
        {
            if (!_state.Enabled) return new StopResult(true, "Mode Paranoïa déjà désactivé.");
            _exec?.Dispose();
            _exec = null;
            _wfp?.Dispose(); // session dynamique : filtres retirés par Windows
            _wfp = null;
            // Le verrouillage d'urgence garde la main sur l'USB tant qu'il est engagé
            if (!lockdownEngaged()) TryUsb(_state.OriginalUsbStart);
            _state = new ParanoiaState(false, null, null);
            Save(_state);
        }
        publish("Warning", "Paranoïa", "Mode Paranoïa désactivé", "Mot de passe de protection vérifié : durcissement levé.");
        return new StopResult(true, "Mode Paranoïa désactivé.");
    }

    /// <summary>Démarrage de processus vu par ETW : contrôle de l'image (hors du thread de trace).</summary>
    public void OnProcessStarted(int pid, string image)
    {
        var guard = _exec;
        if (guard is not null) _ = Task.Run(() => guard.OnProcessStarted(pid, image));
    }

    /// <summary>Réapplique le pare-feu (port du contrôle à distance ouvert ou fermé) si le mode est actif.</summary>
    public void RefreshFirewall()
    {
        lock (_gate)
        {
            if (_state.Enabled) ApplyFirewallLocked();
        }
    }

    private void ApplyLocked()
    {
        TryUsb(UsbDisabled);
        ApplyFirewallLocked();
        ApplyExecutionGuardLocked();
    }

    private void ApplyFirewallLocked()
    {
        _wfp?.Dispose();
        try
        {
            _wfp = new WfpFirewall(dynamic: true);
            // Le contrôle à distance par téléphone reste joignable (le pare-feu Windows le limite au réseau local)
            _wfp.BlockAllInbound("Paranoïa : connexions entrantes", allowedInboundPorts?.Invoke() ?? []);
            int blocked = 0;
            foreach (string tool in UserDirExecutionPolicy.NetworkLolbins)
            {
                string path = Path.Combine(Environment.SystemDirectory, tool);
                if (!File.Exists(path)) continue;
                _wfp.BlockApplicationOutbound(path, "Paranoïa : " + tool);
                blocked++;
            }
            _firewallText = $"WFP : entrées refusées, {blocked} outil(s) système coupé(s) d'Internet";
        }
        catch (NetworkGuardException ex)
        {
            _wfp?.Dispose();
            _wfp = null;
            _firewallText = "pare-feu WFP indisponible";
            logger.LogWarning("Paranoïa, WFP : {Message}", ex.Message);
        }
    }

    private void ApplyExecutionGuardLocked()
    {
        _exec?.Dispose();
        _exec = new UserDirExecutionGuard(IsTrusted, Terminate, ProcessAncestry.ImagePath);
        _exec.Blocked += b => publish("Critical", "Paranoïa", "Exécution bloquée",
            $"{Path.GetFileName(b.ImagePath)} (non signé, lancé depuis {Path.GetDirectoryName(b.ImagePath)}) : " +
            (b.Terminated ? "processus arrêté." : "arrêt impossible."));
    }

    private bool IsTrusted(string path) => _authenticode.EvaluateAsync(path).GetAwaiter().GetResult().IsTrusted;

    private bool Terminate(int pid) =>
        actions.TerminateProcessAsync(pid, "Mode Paranoïa : exécutable non signé lancé depuis un dossier utilisateur").GetAwaiter().GetResult().Success;

    private void TryUsb(int? value)
    {
        try { usb.SetUsbStorageStart(value); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            logger.LogWarning("Paranoïa, USB : {Message}", ex.Message);
        }
    }

    private void Save(ParanoiaState state)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(statePath)!);
            File.WriteAllText(statePath, JsonSerializer.Serialize(state));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning("Paranoïa : état non enregistré ({Message})", ex.Message);
        }
    }

    private static ParanoiaState? Load(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<ParanoiaState>(File.ReadAllText(path)) : null; }
        catch (Exception ex) when (ex is IOException or JsonException) { return null; }
    }

    public void Dispose()
    {
        _exec?.Dispose();
        _wfp?.Dispose();
    }
}
