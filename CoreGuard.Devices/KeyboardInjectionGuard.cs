namespace CoreGuard.Devices;

/// <summary>Alerte : frappe automatique détectée et bloquée.</summary>
public sealed record InjectionAlert(CadenceVerdict Verdict, DateTime WhenUtc, TimeSpan BlockedFor, bool Vigilant);

/// <summary>
/// Décision « laisser passer / bloquer » pour chaque appui de touche (logique pure, horloge injectable).
/// À la détection, toutes les frappes sont avalées pendant <see cref="BlockDuration"/> ; tant que l'injection
/// continue, le blocage est prolongé. L'utilisateur garde toujours Ctrl+Alt+Suppr (non interceptable).
/// </summary>
public sealed class KeyboardInjectionGuard
{
    public static readonly TimeSpan BlockDuration = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan VigilanceDuration = TimeSpan.FromSeconds(60);

    private readonly KeystrokeCadenceAnalyzer _analyzer = new();
    private readonly HashSet<int> _down = [];
    private readonly object _gate = new();
    private double _blockedUntilMs = double.MinValue;
    private double _vigilantUntilMs = double.MinValue;

    /// <summary>Levé (depuis le thread du hook : à traiter rapidement) au début de chaque blocage.</summary>
    public event EventHandler<InjectionAlert>? InjectionDetected;

    /// <summary>Un nouveau clavier vient d'être branché : seuils abaissés pendant <see cref="VigilanceDuration"/>.</summary>
    public void EnterVigilance(double nowMs)
    {
        lock (_gate) _vigilantUntilMs = nowMs + VigilanceDuration.TotalMilliseconds;
    }

    public bool IsBlocking(double nowMs)
    {
        lock (_gate) return nowMs < _blockedUntilMs;
    }

    /// <summary>Appui de touche. Renvoie vrai si la frappe doit être avalée.</summary>
    public bool OnKeyDown(int virtualKey, bool injected, double nowMs)
    {
        InjectionAlert? alert = null;
        bool swallow;
        lock (_gate)
        {
            // Répétition automatique (touche maintenue, sans relâchement) : ignorée par l'analyse
            bool repeat = !_down.Add(virtualKey);
            if (!repeat)
            {
                _analyzer.Vigilant = nowMs < _vigilantUntilMs;
                CadenceVerdict? verdict = _analyzer.Record(nowMs, injected);
                if (verdict is not null)
                {
                    bool wasBlocking = nowMs < _blockedUntilMs;
                    _blockedUntilMs = nowMs + BlockDuration.TotalMilliseconds;
                    if (!wasBlocking)
                        alert = new InjectionAlert(verdict, DateTime.UtcNow, BlockDuration, _analyzer.Vigilant);
                }
            }
            swallow = nowMs < _blockedUntilMs;
        }

        if (alert is not null)
        {
            try { InjectionDetected?.Invoke(this, alert); } catch { /* un abonné fautif ne bloque pas le hook */ }
        }
        return swallow;
    }

    /// <summary>Relâchement d'une touche (sert à distinguer une répétition automatique d'un nouvel appui).</summary>
    public bool OnKeyUp(int virtualKey, double nowMs)
    {
        lock (_gate)
        {
            _down.Remove(virtualKey);
            return nowMs < _blockedUntilMs;
        }
    }
}
