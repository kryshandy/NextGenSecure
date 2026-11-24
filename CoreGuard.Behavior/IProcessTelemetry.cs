namespace CoreGuard.Behavior;

/// <summary>Source de télémétrie processus. Les alertes sont émises depuis un thread d'arrière-plan.</summary>
public interface IProcessTelemetry : IDisposable
{
    /// <summary>Vrai si l'écoute est active.</summary>
    bool IsRunning { get; }

    /// <summary>Levé pour chaque alerte comportementale.</summary>
    event EventHandler<BehaviorAlert>? AlertRaised;

    /// <summary>Levé pour un avertissement non fatal (ex. droits administrateur manquants).</summary>
    event EventHandler<string>? Warning;

    /// <summary>Démarre l'écoute. Renvoie false (sans lever) si impossible.</summary>
    bool Start();

    /// <summary>Arrête l'écoute proprement (idempotent).</summary>
    void Stop();
}
