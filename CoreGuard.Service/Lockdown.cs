using System.Runtime.Versioning;
using System.Text.Json;
using CoreGuard.Network;
using Microsoft.Win32;

namespace CoreGuard.Service;

/// <summary>Leviers système du verrouillage (abstraits pour être testés sans toucher à la machine).</summary>
public interface ILockdownBackend
{
    /// <summary>Valeur « Start » du pilote de stockage USB (3 = activé, 4 = désactivé ; null = clé absente).</summary>
    int? GetUsbStorageStart();
    void SetUsbStorageStart(int? value);

    /// <summary>Stratégie « Empêcher l'installation des périphériques non décrits » (null = non définie).</summary>
    int? GetDenyNewDevices();
    void SetDenyNewDevices(int? value);

    bool IsNetworkCut { get; }
    void SetNetworkCut(bool cut);
}

/// <summary>État persistant du verrouillage (survit au redémarrage du service et de la machine).</summary>
public sealed record LockdownState(
    bool Engaged,
    DateTime? SinceUtc,
    string? Reason,
    bool NetworkCut,
    int? SavedUsbStorageStart,
    int? SavedDenyNewDevices,
    bool SavedValuesKnown);

/// <summary>
/// Verrouillage d'urgence du PC, côté système (service SYSTEM) :
/// - clés et disques USB bloqués (pilote USBSTOR désactivé) ;
/// - aucun NOUVEAU périphérique accepté (stratégie DeviceInstall « DenyUnspecified ») : un BadUSB ou un clavier
///   inconnu branché pendant le verrouillage ne s'installe pas ; le clavier et la souris déjà connus continuent de
///   fonctionner pour que le propriétaire puisse saisir son mot de passe ;
/// - coupure réseau optionnelle (pare-feu : tout le trafic sortant bloqué) ;
/// - l'écran de verrouillage et le blocage clavier/souris sont gérés par l'interface dans la session utilisateur.
/// Le déverrouillage exige le mot de passe de protection (défi-réponse HMAC) et restaure les valeurs d'origine.
/// </summary>
public sealed class LockdownController
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private readonly ILockdownBackend _backend;
    private readonly string _statePath;
    private readonly object _gate = new();
    private LockdownState _state;

    public LockdownController(ILockdownBackend backend, string statePath)
    {
        _backend = backend;
        _statePath = statePath;
        _state = Load(statePath) ?? new LockdownState(false, null, null, false, null, null, false);
    }

    public LockdownState State { get { lock (_gate) return _state; } }

    /// <summary>Levé après chaque changement d'état.</summary>
    public event Action<LockdownState>? Changed;

    /// <summary>Levé quand un levier n'a pas pu être appliqué (droits insuffisants…) : les autres le sont quand même.</summary>
    public event Action<string>? Warning;

    /// <summary>Au démarrage du service : un verrouillage en cours est ré-appliqué (redémarrage, crash…).</summary>
    public void Reassert()
    {
        lock (_gate)
        {
            if (!_state.Engaged) return;
            ApplyBlocks(_state.NetworkCut);
        }
    }

    /// <summary>Verrouille. Sans effet (et sans écraser les valeurs d'origine) si déjà verrouillé.</summary>
    public LockdownState Engage(string reason, bool cutNetwork)
    {
        LockdownState state;
        lock (_gate)
        {
            if (_state.Engaged) return _state;
            // Les valeurs d'origine sont sauvegardées AVANT toute modification
            int? usb = null, deny = null;
            bool known = Try("lecture de l'état USB", () => { usb = _backend.GetUsbStorageStart(); deny = _backend.GetDenyNewDevices(); });
            var saved = new LockdownState(true, DateTime.UtcNow, reason, cutNetwork, usb, deny, SavedValuesKnown: known);
            Save(saved);
            _state = saved;
            ApplyBlocks(cutNetwork);
            state = _state;
        }
        Changed?.Invoke(state);
        return state;
    }

    /// <summary>Déverrouille (à n'appeler qu'après vérification du mot de passe) et restaure l'état d'origine.</summary>
    public LockdownState Release()
    {
        LockdownState state;
        lock (_gate)
        {
            if (!_state.Engaged) return _state;
            if (_state.SavedValuesKnown)
            {
                Try("restauration du stockage USB", () => _backend.SetUsbStorageStart(_state.SavedUsbStorageStart));
                Try("restauration de la stratégie des périphériques", () => _backend.SetDenyNewDevices(_state.SavedDenyNewDevices));
            }
            if (_state.NetworkCut) Try("rétablissement du réseau", () => _backend.SetNetworkCut(false));
            _state = new LockdownState(false, null, null, false, null, null, false);
            Save(_state);
            state = _state;
        }
        Changed?.Invoke(state);
        return state;
    }

    private void ApplyBlocks(bool cutNetwork)
    {
        Try("blocage du stockage USB", () => _backend.SetUsbStorageStart(4));
        Try("refus des nouveaux périphériques", () => _backend.SetDenyNewDevices(1));
        if (cutNetwork) Try("coupure du réseau", () => _backend.SetNetworkCut(true));
    }

    private bool Try(string what, Action action)
    {
        try
        {
            action();
            return true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Warning?.Invoke($"{what} impossible ({ex.GetType().Name})");
            return false;
        }
    }

    private void Save(LockdownState state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
        string temp = _statePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, Json));
        File.Move(temp, _statePath, overwrite: true);
    }

    private static LockdownState? Load(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<LockdownState>(File.ReadAllText(path)) : null; }
        catch (Exception ex) when (ex is IOException or JsonException) { return null; }
    }
}

/// <summary>Leviers réels : registre (SYSTEM requis) et pare-feu Windows.</summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryLockdownBackend(INetworkGuard firewall) : ILockdownBackend
{
    private const string UsbStorKey = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
    private const string RestrictionsKey = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";

    public int? GetUsbStorageStart() => ReadDword(UsbStorKey, "Start");
    public void SetUsbStorageStart(int? value) => WriteDword(UsbStorKey, "Start", value);

    public int? GetDenyNewDevices() => ReadDword(RestrictionsKey, "DenyUnspecified");
    public void SetDenyNewDevices(int? value) => WriteDword(RestrictionsKey, "DenyUnspecified", value);

    public bool IsNetworkCut => firewall.IsKillSwitchActive;
    public void SetNetworkCut(bool cut) { if (firewall.CanManageFirewall) firewall.KillSwitch(cut); }

    private static int? ReadDword(string key, string name)
    {
        using var k = Registry.LocalMachine.OpenSubKey(key);
        return k?.GetValue(name) is int v ? v : null;
    }

    private static void WriteDword(string key, string name, int? value)
    {
        if (value is null)
        {
            using var existing = Registry.LocalMachine.OpenSubKey(key, writable: true);
            existing?.DeleteValue(name, throwOnMissingValue: false);
            return;
        }
        using var k = Registry.LocalMachine.CreateSubKey(key, writable: true);
        k.SetValue(name, value.Value, RegistryValueKind.DWord);
    }
}
