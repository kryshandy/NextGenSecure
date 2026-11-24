namespace CoreGuard.RealTime;

/// <summary>
/// Point d'intégration avec la couche service : réaction aux menaces détectées.
/// L'implémentation réelle (kill, quarantaine) est fournie par le service.
/// </summary>
public interface IThreatResponder
{
    /// <summary>Appelé dès qu'un canari est touché.</summary>
    Task OnCanaryTriggeredAsync(CanaryAlert alert, CancellationToken ct);

    /// <summary>Termine le processus désigné.</summary>
    Task KillProcessAsync(int pid);

    /// <summary>Met en quarantaine un fichier pour la raison donnée.</summary>
    Task QuarantineAsync(string path, string reason);
}
