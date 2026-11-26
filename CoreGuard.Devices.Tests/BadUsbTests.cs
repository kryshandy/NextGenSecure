using CoreGuard.Devices;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace CoreGuard.Devices.Tests;

[TestClass]
public sealed class BadUsbTests
{
    // Frappe d'une suite de touches distinctes (appui puis relâchement), aux instants donnés (ms)
    private static (bool AnySwallowed, int Alerts) Type(KeyboardInjectionGuard guard, IEnumerable<double> times, bool injected = false)
    {
        int alerts = 0;
        guard.InjectionDetected += (_, _) => Interlocked.Increment(ref alerts);
        bool swallowed = false;
        int key = 0x41;
        foreach (double t in times)
        {
            swallowed |= guard.OnKeyDown(key, injected, t);
            guard.OnKeyUp(key, t + 0.01);
            key = key == 0x5A ? 0x41 : key + 1;
        }
        return (swallowed, alerts);
    }

    private static IEnumerable<double> Regular(int count, double intervalMs, double start = 0) =>
        Enumerable.Range(0, count).Select(i => start + i * intervalMs);

    [TestMethod]
    public void Une_frappe_humaine_rapide_et_irreguliere_passe()
    {
        // ~14 car/s, intervalles de 30 à 150 ms
        var rnd = new Random(42);
        double t = 0;
        var times = Enumerable.Range(0, 300).Select(_ => t += 30 + rnd.NextDouble() * 120).ToList();
        var (swallowed, alerts) = Type(new KeyboardInjectionGuard(), times);
        Assert.IsFalse(swallowed);
        Assert.AreEqual(0, alerts);
    }

    [TestMethod]
    public void Une_rafale_de_BadUSB_est_detectee_et_bloquee()
    {
        // Comme le spécimen 04 : 16 caractères quasi simultanés puis 10 ms de pause (~1500 car/s)
        var times = new List<double>();
        double t = 0;
        for (int burst = 0; burst < 10; burst++, t += 10)
            for (int i = 0; i < 16; i++) times.Add(t + i * 0.02);

        var guard = new KeyboardInjectionGuard();
        var (swallowed, alerts) = Type(guard, times, injected: true);
        Assert.IsTrue(swallowed);
        Assert.AreEqual(1, alerts, "une seule alerte par épisode de blocage");
        Assert.IsTrue(guard.IsBlocking(times[^1] + 1000));
    }

    [TestMethod]
    public void Une_cadence_de_machine_moderee_mais_reguliere_est_detectee()
    {
        // Ducky avec DEFAULT_DELAY : 50 car/s parfaitement réguliers
        CadenceVerdict? verdict = null;
        var guard = new KeyboardInjectionGuard();
        guard.InjectionDetected += (_, a) => verdict = a.Verdict;
        Type(guard, Regular(40, 20));
        Assert.IsNotNull(verdict);
        Assert.AreEqual(InjectionKind.MachineRegularity, verdict.Kind);
        Assert.AreEqual(0.0, verdict.CoefficientOfVariation, 0.01);
    }

    [TestMethod]
    public void La_repetition_d_une_touche_maintenue_est_ignoree()
    {
        // Touche maintenue : 200 appuis à 33 ms sans relâchement (répétition automatique Windows)
        var guard = new KeyboardInjectionGuard();
        bool swallowed = false;
        foreach (double t in Regular(200, 33)) swallowed |= guard.OnKeyDown(0x41, false, t);
        Assert.IsFalse(swallowed);
    }

    [TestMethod]
    public void En_vigilance_le_seuil_de_regularite_est_abaisse()
    {
        // 30 car/s réguliers : toléré normalement, détecté juste après le branchement d'un clavier
        Assert.IsFalse(Type(new KeyboardInjectionGuard(), Regular(60, 33.3)).AnySwallowed);

        var vigilant = new KeyboardInjectionGuard();
        vigilant.EnterVigilance(0);
        Assert.IsTrue(Type(vigilant, Regular(60, 33.3)).AnySwallowed);
    }

    [TestMethod]
    public void Le_blocage_expire_puis_la_frappe_reprend()
    {
        var guard = new KeyboardInjectionGuard();
        Type(guard, Regular(40, 1)); // 1000 car/s → blocage
        double end = 39 + KeyboardInjectionGuard.BlockDuration.TotalMilliseconds;
        Assert.IsTrue(guard.IsBlocking(end - 1));
        Assert.IsFalse(guard.IsBlocking(end + 1));
        Assert.IsFalse(guard.OnKeyDown(0x31, false, end + 5000), "une frappe humaine après le blocage passe");
    }

    [TestMethod]
    public void Une_injection_qui_continue_prolonge_le_blocage()
    {
        var guard = new KeyboardInjectionGuard();
        Type(guard, Regular(200, 1)); // 200 ms d'injection continue à 1000 car/s
        Assert.IsTrue(guard.IsBlocking(199 + KeyboardInjectionGuard.BlockDuration.TotalMilliseconds - 1));
    }

    [TestMethod]
    public void Moins_de_frappes_que_la_fenetre_ne_declenche_rien()
    {
        var analyzer = new KeystrokeCadenceAnalyzer();
        for (int i = 0; i < KeystrokeCadenceAnalyzer.Window - 1; i++)
            Assert.IsNull(analyzer.Record(i * 0.5, true));
    }

    [TestMethod]
    public void La_part_de_frappes_injectees_est_mesuree()
    {
        var analyzer = new KeystrokeCadenceAnalyzer();
        CadenceVerdict? v = null;
        for (int i = 0; i < KeystrokeCadenceAnalyzer.Window; i++) v = analyzer.Record(i, injected: i % 2 == 0);
        Assert.IsNotNull(v);
        Assert.AreEqual(0.5, v.InjectedRatio, 0.01);
    }

    [TestMethod]
    public void La_liste_des_claviers_se_lit_sans_erreur()
    {
        var keyboards = BadUsbMonitor.ListKeyboards();
        Assert.IsNotNull(keyboards); // une machine sans clavier physique (VM, CI) renvoie une liste vide
    }
}

[TestClass]
public sealed class InputLockTests
{
    [TestMethod]
    [DataRow(0x5B, false, false, true)]   // touche Windows
    [DataRow(0x09, true, false, true)]    // Alt+Tab
    [DataRow(0x73, true, false, true)]    // Alt+F4
    [DataRow(0x1B, false, true, true)]    // Ctrl+Échap
    [DataRow(0x41, false, false, false)]  // lettre A : saisie du mot de passe
    [DataRow(0x0D, false, false, false)]  // Entrée
    public void Seuls_les_raccourcis_systeme_sont_bloques_sur_l_ecran_de_verrouillage(int vk, bool alt, bool ctrl, bool blocked)
    {
        Assert.AreEqual(blocked, InputLockHook.ShouldBlock(vk, alt, ctrl, lockWindowForeground: true));
    }

    [TestMethod]
    public void Hors_de_l_ecran_de_verrouillage_tout_est_bloque()
    {
        Assert.IsTrue(InputLockHook.ShouldBlock(0x41, false, false, lockWindowForeground: false));
    }
}
