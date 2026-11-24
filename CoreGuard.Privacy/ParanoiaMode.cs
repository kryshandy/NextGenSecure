namespace CoreGuard.Privacy;

/// <summary>Intentions de durcissement ; leur application réelle est câblée par la couche service.</summary>
public sealed record HardeningPolicy(bool BlockNewUsb, bool StrictFirewall, bool BlockExecFromUserDirs)
{
    public static readonly HardeningPolicy Off = new(false, false, false);
    public static readonly HardeningPolicy Paranoid = new(true, true, true);
}

/// <summary>Interrupteur « Mode Paranoïa » : expose la politique courante et notifie les changements.</summary>
public sealed class ParanoiaMode
{
    private readonly object _gate = new();
    private bool _enabled;

    /// <summary>Levé uniquement quand l'état change réellement.</summary>
    public event EventHandler<HardeningPolicy>? StateChanged;

    public bool IsEnabled { get { lock (_gate) return _enabled; } }

    public HardeningPolicy CurrentPolicy => IsEnabled ? HardeningPolicy.Paranoid : HardeningPolicy.Off;

    /// <summary>Active/désactive. Retourne vrai si l'état a changé (idempotent sinon).</summary>
    public bool SetEnabled(bool enabled)
    {
        lock (_gate)
        {
            if (_enabled == enabled) return false;
            _enabled = enabled;
        }
        StateChanged?.Invoke(this, enabled ? HardeningPolicy.Paranoid : HardeningPolicy.Off);
        return true;
    }

    /// <summary>Inverse l'état ; retourne le nouvel état.</summary>
    public bool Toggle()
    {
        bool now;
        lock (_gate) { _enabled = !_enabled; now = _enabled; }
        StateChanged?.Invoke(this, now ? HardeningPolicy.Paranoid : HardeningPolicy.Off);
        return now;
    }
}
