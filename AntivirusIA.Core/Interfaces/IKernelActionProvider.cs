namespace AntivirusIA.Core.Interfaces;

/// <summary>
/// Actions de réponse aux menaces (arrêt, suspension, isolation réseau, protection de fichiers et de soi-même).
/// Aujourd'hui fourni en mode utilisateur par <c>UserModeActionProvider</c> (CoreGuard.Response).
/// Le futur driver Rust (Ring 0) fournira une autre implémentation de ce même contrat, substituable
/// dans la composition root sans toucher aux modules qui l'utilisent.
/// Aucune méthode ne lève d'exception pour un échec attendu : le résultat dit ce qui s'est passé.
/// </summary>
public interface IKernelActionProvider
{
    /// <summary>Nom affichable du fournisseur (ex. « Mode utilisateur »).</summary>
    string Name { get; }

    /// <summary>Vrai si les actions passent par un driver noyau (blocages inviolables depuis le mode utilisateur).</summary>
    bool IsKernelBacked { get; }

    /// <summary>Termine un processus. Refuse les processus critiques du système et CoreGuard lui-même.</summary>
    Task<ActionResult> TerminateProcessAsync(int pid, string reason, CancellationToken ct = default);

    /// <summary>Gèle tous les threads d'un processus (le temps d'analyser ou de décider).</summary>
    Task<ActionResult> SuspendProcessAsync(int pid, CancellationToken ct = default);

    /// <summary>Reprend un processus précédemment suspendu.</summary>
    Task<ActionResult> ResumeProcessAsync(int pid, CancellationToken ct = default);

    /// <summary>Coupe les connexions sortantes de l'exécutable du processus (règle de pare-feu).</summary>
    Task<ActionResult> BlockNetworkAsync(int pid, string? imagePath, CancellationToken ct = default);

    /// <summary>Restreint les droits NTFS d'un fichier : héritage coupé, exécution refusée à tous.</summary>
    Task<ActionResult> ProtectFileAsync(string path, CancellationToken ct = default);

    /// <summary>Durcit la DACL du processus CoreGuard : arrêt, suspension et injection refusés aux autres processus.</summary>
    Task<ActionResult> ProtectSelfAsync(CancellationToken ct = default);
}

/// <summary>Résultat d'une action de réponse.</summary>
public sealed record ActionResult(bool Success, string Message)
{
    public static ActionResult Ok(string message) => new(true, message);
    public static ActionResult Fail(string message) => new(false, message);
}
