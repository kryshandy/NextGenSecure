using AntivirusIA.Core.Interfaces;
using AntivirusIA.UI.Models;
using AntivirusIA.UI.Views;
using CoreGuard.Devices;
using CoreGuard.Ipc;

namespace AntivirusIA.UI.Services;

/// <summary>
/// Côté interface du verrouillage d'urgence. Quand le service annonce un verrouillage (bouton, BadUSB, ordre à
/// distance, ou verrouillage toujours actif après un redémarrage) :
/// 1. la session Windows est verrouillée (écran de connexion) ;
/// 2. au retour, l'écran CoreGuard couvre tous les moniteurs et le clavier ne sert plus qu'à y saisir le mot de passe
///    de protection (raccourcis système bloqués) ;
/// 3. le processus de l'interface est durci (le Gestionnaire des tâches ne peut pas le fermer).
/// Le déverrouillage passe par le service (défi-réponse HMAC) : lui seul lève les blocages USB / réseau.
/// </summary>
public sealed class LockdownUiController(ServiceLink service, AlertHub alerts, IKernelActionProvider actions) : IDisposable
{
    private LockScreenWindow? _window;
    private InputLockHook? _hook;
    private bool _processHardened;

    public void Start()
    {
        service.StatusChanged += () => UiThread.Post(Sync);
        UiThread.Post(Sync);
    }

    /// <summary>Verrouille le PC maintenant (via le service). Faux si le service n'est pas joignable.</summary>
    public async Task<StopResult> LockNowAsync(string reason, bool cutNetwork)
    {
        var result = await service.EngageLockdownAsync(reason, cutNetwork);
        if (!result.Accepted)
            alerts.Publish(AlertSeverity.Warning, "Verrouillage", "Verrouillage impossible", result.Message);
        return result;
    }

    private void Sync()
    {
        bool engaged = service.LockdownEngaged;
        if (engaged && _window is null) Show(service.LockdownText ?? "verrouillage d'urgence");
        else if (!engaged && _window is not null) Hide();
    }

    private void Show(string reason)
    {
        if (!_processHardened)
        {
            _processHardened = true;
            _ = actions.ProtectSelfAsync(); // jusqu'à la fermeture de l'application
        }

        _window = new LockScreenWindow(reason, service.RequestUnlockAsync);
        _window.Show();
        _hook = new InputLockHook(() => _window?.Handle ?? IntPtr.Zero);
        if (!_hook.Start()) { _hook.Dispose(); _hook = null; }
        InputLockHook.LockWindowsSession();
    }

    private void Hide()
    {
        _hook?.Dispose();
        _hook = null;
        _window?.Release();
        _window = null;
        alerts.Publish(AlertSeverity.Info, "Verrouillage", "PC déverrouillé", "Clavier, USB et réseau rétablis.");
    }

    public void Dispose() => _hook?.Dispose();
}
