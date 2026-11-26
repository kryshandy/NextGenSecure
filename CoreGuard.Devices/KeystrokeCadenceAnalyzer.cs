namespace CoreGuard.Devices;

/// <summary>Raison d'une détection de frappe automatique.</summary>
public enum InjectionKind
{
    /// <summary>Débit impossible pour un humain (rafale de périphérique HID ou d'injection logicielle).</summary>
    ExtremeRate,
    /// <summary>Débit élevé ET intervalles quasi constants : cadence de machine (Rubber Ducky avec délais).</summary>
    MachineRegularity
}

/// <summary>Résultat d'une détection.</summary>
/// <param name="CharsPerSecond">Débit mesuré sur la fenêtre d'analyse.</param>
/// <param name="CoefficientOfVariation">Écart-type / moyenne des intervalles (0 = parfaitement régulier).</param>
/// <param name="InjectedRatio">Part des frappes signalées « injectées » par Windows (SendInput) ; 0 pour un vrai périphérique.</param>
public sealed record CadenceVerdict(InjectionKind Kind, double CharsPerSecond, double CoefficientOfVariation, double InjectedRatio);

/// <summary>
/// Analyse la cadence des appuis de touche (logique pure, sans dépendance Windows : testable).
/// Un humain tape 5 à 12 caractères/s, avec des pointes de ~20 sur quelques touches et des intervalles très
/// irréguliers. Un BadUSB (Rubber Ducky, Digispark…) tape des centaines de caractères par seconde, ou, s'il est
/// configuré avec des délais, à un rythme rapide et métronomique. Deux règles :
/// - débit &gt; <see cref="ExtremeRate"/> car/s sur la fenêtre : détecté quelle que soit la régularité ;
/// - débit ≥ <see cref="RegularRate"/> car/s ET coefficient de variation &lt; <see cref="MaxRegularCv"/>.
/// Les répétitions automatiques d'une touche maintenue (≤ ~30/s) sont filtrées en amont par l'appelant.
/// En vigilance (nouveau clavier branché), le seuil de régularité est abaissé.
/// </summary>
public sealed class KeystrokeCadenceAnalyzer
{
    public const int Window = 30;
    // 200 car/s soutenus sur 30 frappes : ~8 fois le maximum humain. (La spécification cite 500 car/s ; mesuré sur
    // le spécimen 04 et une vraie injection SendInput, le débit observé tombe vers 500 : 200 laisse une marge nette.)
    public const double ExtremeRate = 200;
    public const double RegularRate = 40;
    public const double VigilantRegularRate = 25;
    public const double MaxRegularCv = 0.3;

    private readonly long[] _times = new long[Window];
    private readonly bool[] _injected = new bool[Window];
    private int _count, _next;

    /// <summary>Mode vigilance : actif après le branchement d'un nouveau clavier.</summary>
    public bool Vigilant { get; set; }

    /// <summary>Enregistre un appui (horodatage en millisecondes, monotone) ; renvoie un verdict si la cadence est celle d'une machine.</summary>
    public CadenceVerdict? Record(double timestampMs, bool injected)
    {
        _times[_next] = (long)(timestampMs * 1000); // microsecondes : garde la précision des rafales
        _injected[_next] = injected;
        _next = (_next + 1) % Window;
        if (_count < Window) _count++;
        return _count < Window ? null : Evaluate();
    }

    public void Reset()
    {
        _count = 0;
        _next = 0;
    }

    private CadenceVerdict? Evaluate()
    {
        // Ordre chronologique : la plus ancienne entrée est à _next
        Span<double> intervals = stackalloc double[Window - 1];
        long previous = _times[_next];
        for (int i = 1; i < Window; i++)
        {
            long t = _times[(_next + i) % Window];
            intervals[i - 1] = Math.Max(0, t - previous) / 1000.0; // ms
            previous = t;
        }

        double spanMs = 0;
        foreach (double d in intervals) spanMs += d;
        double rate = spanMs <= 0 ? double.PositiveInfinity : (Window - 1) * 1000.0 / spanMs;

        double mean = spanMs / intervals.Length;
        double variance = 0;
        foreach (double d in intervals) variance += (d - mean) * (d - mean);
        double cv = mean <= 0 ? 0 : Math.Sqrt(variance / intervals.Length) / mean;

        int injected = 0;
        foreach (bool b in _injected) if (b) injected++;
        double injectedRatio = (double)injected / Window;

        if (rate > ExtremeRate)
            return new CadenceVerdict(InjectionKind.ExtremeRate, rate, cv, injectedRatio);
        if (rate >= (Vigilant ? VigilantRegularRate : RegularRate) && cv < MaxRegularCv)
            return new CadenceVerdict(InjectionKind.MachineRegularity, rate, cv, injectedRatio);
        return null;
    }
}
