using CoreGuard.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoreGuard.Service.Tests;

[TestClass]
public sealed class LockdownTests
{
    private sealed class FakeBackend : ILockdownBackend
    {
        public int? UsbStart { get; set; } = 3;
        public int? Deny { get; set; }
        public bool NetworkCut { get; set; }
        public bool FailUsb { get; set; }

        public int? GetUsbStorageStart() => UsbStart;
        public void SetUsbStorageStart(int? value) { if (FailUsb) throw new UnauthorizedAccessException(); UsbStart = value; }
        public int? GetDenyNewDevices() => Deny;
        public void SetDenyNewDevices(int? value) => Deny = value;
        public bool IsNetworkCut => NetworkCut;
        public void SetNetworkCut(bool cut) => NetworkCut = cut;
    }

    private static string TempState() => Path.Combine(Path.GetTempPath(), "cg_lock_" + Guid.NewGuid().ToString("N"), "lockdown.json");

    [TestMethod]
    public void Le_verrouillage_bloque_puis_le_deverrouillage_restaure_exactement()
    {
        var backend = new FakeBackend { UsbStart = 3, Deny = null };
        var lockdown = new LockdownController(backend, TempState());

        lockdown.Engage("test", cutNetwork: true);
        Assert.AreEqual(4, backend.UsbStart, "stockage USB désactivé");
        Assert.AreEqual(1, backend.Deny, "nouveaux périphériques refusés");
        Assert.IsTrue(backend.NetworkCut);
        Assert.IsTrue(lockdown.State.Engaged);

        lockdown.Release();
        Assert.AreEqual(3, backend.UsbStart);
        Assert.IsNull(backend.Deny, "une stratégie absente à l'origine est supprimée, pas forcée à 0");
        Assert.IsFalse(backend.NetworkCut);
        Assert.IsFalse(lockdown.State.Engaged);
    }

    [TestMethod]
    public void Un_second_verrouillage_n_ecrase_pas_les_valeurs_d_origine()
    {
        var backend = new FakeBackend { UsbStart = 3 };
        var lockdown = new LockdownController(backend, TempState());
        lockdown.Engage("premier", false);
        lockdown.Engage("second", false); // USB déjà à 4 : ne doit pas devenir la valeur « d'origine »
        Assert.AreEqual("premier", lockdown.State.Reason);
        lockdown.Release();
        Assert.AreEqual(3, backend.UsbStart);
    }

    [TestMethod]
    public void Le_verrouillage_survit_au_redemarrage_et_est_reapplique()
    {
        string path = TempState();
        var backend = new FakeBackend { UsbStart = 3 };
        new LockdownController(backend, path).Engage("vol", false);

        backend.UsbStart = 3; // quelqu'un a réactivé l'USB pendant que le service était arrêté
        var restarted = new LockdownController(backend, path);
        Assert.IsTrue(restarted.State.Engaged);
        restarted.Reassert();
        Assert.AreEqual(4, backend.UsbStart);

        restarted.Release();
        Assert.AreEqual(3, backend.UsbStart, "valeur d'origine relue depuis le disque");
    }

    [TestMethod]
    public void Un_levier_en_echec_n_empeche_pas_le_reste()
    {
        var backend = new FakeBackend { FailUsb = true };
        var lockdown = new LockdownController(backend, TempState());
        var warnings = new List<string>();
        lockdown.Warning += warnings.Add;

        lockdown.Engage("test", false);
        Assert.IsTrue(lockdown.State.Engaged);
        Assert.AreEqual(1, backend.Deny);
        Assert.IsTrue(warnings.Any(w => w.Contains("USB")));
    }

    // ---------- Verrouillage à distance ----------

    [TestMethod]
    public void Le_code_a_distance_est_verifie_sans_etre_stocke_en_clair()
    {
        var config = RemoteLockConfig.Create(["C:\\x"], "Mon-code-secret-42", iterations: 1_000);
        StringAssert.DoesNotMatch(System.Text.Json.JsonSerializer.Serialize(config), new System.Text.RegularExpressions.Regex("Mon-code"));
        Assert.IsTrue(config.Verify("Mon-code-secret-42"));
        Assert.IsTrue(config.Verify("  Mon-code-secret-42\r\n"), "espaces et retour à la ligne du téléphone tolérés");
        Assert.IsFalse(config.Verify("mon-code-secret-42"));
        Assert.ThrowsExactly<ArgumentException>(() => RemoteLockConfig.Create(["C:\\x"], "court"));
    }

    [TestMethod]
    public void Un_fichier_ordre_avec_le_bon_code_verrouille_et_n_est_pas_rejoue()
    {
        string folder = Path.Combine(Path.GetTempPath(), "cg_remote_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var config = RemoteLockConfig.Create([folder], "Mon-code-secret-42", iterations: 1_000);
            var engaged = new List<string>();
            var refused = new List<string>();
            using var watcher = new RemoteLockWatcher(config, engaged.Add, (t, _) => refused.Add(t), NullLogger.Instance);

            File.WriteAllText(Path.Combine(folder, "CoreGuard-VERROUILLER-faux.txt"), "mauvais code");
            File.WriteAllText(Path.Combine(folder, "CoreGuard-VERROUILLER.txt"), "Mon-code-secret-42");
            watcher.Scan();

            Assert.AreEqual(1, engaged.Count, "un seul ordre valide");
            Assert.AreEqual(1, refused.Count, "le mauvais code est signalé");
            Assert.AreEqual(0, Directory.GetFiles(folder, "CoreGuard-VERROUILLER*.txt").Count(f => !f.Contains(".traite-") && !f.Contains(".refuse-")),
                "les fichiers-ordres sont renommés");

            watcher.Scan();
            Assert.AreEqual(1, engaged.Count, "un ordre traité n'est pas rejoué");
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }
}
