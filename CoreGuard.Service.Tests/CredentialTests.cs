using CoreGuard.Service;

namespace CoreGuard.Service.Tests;

[TestClass]
public sealed class CredentialTests
{
    private static readonly SignerInfo Google = new(true, "Google LLC");
    private static readonly SignerInfo MicrosoftSigner = new(true, "Microsoft Corporation");
    private static readonly SignerInfo Unsigned = new(false, null);
    private static string Win(string rel) => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), rel);

    // ---------- Politique ----------

    [TestMethod]
    public void Chrome_signe_par_Google_peut_lire_ses_identifiants()
    {
        Assert.AreEqual(CredentialDecision.Allow,
            CredentialAccessPolicy.Decide(@"C:\Program Files\Google\Chrome\Application\chrome.exe", false, Google));
    }

    [TestMethod]
    public void Un_faux_chrome_non_signe_est_arrete()
    {
        Assert.AreEqual(CredentialDecision.Stop,
            CredentialAccessPolicy.Decide(@"C:\Users\x\AppData\Local\Temp\chrome.exe", false, Unsigned));
    }

    [TestMethod]
    public void Un_chrome_signe_par_un_autre_editeur_est_arrete()
    {
        Assert.AreEqual(CredentialDecision.Stop,
            CredentialAccessPolicy.Decide(@"C:\Temp\chrome.exe", false, new SignerInfo(true, "Evil Corp")));
    }

    [TestMethod]
    public void Edge_peut_importer_les_mots_de_passe_de_Chrome()
    {
        Assert.AreEqual(CredentialDecision.Allow,
            CredentialAccessPolicy.Decide(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", false, MicrosoftSigner));
    }

    [TestMethod]
    [DataRow(@"System32\WindowsPowerShell\v1.0\powershell.exe")]
    [DataRow(@"System32\cmd.exe")]
    public void Un_outil_systeme_signe_mais_non_navigateur_est_arrete(string rel)
    {
        // Les voleurs utilisent souvent PowerShell ou « cmd /c copy » : signés Microsoft, mais pas des navigateurs
        Assert.AreEqual(CredentialDecision.Stop, CredentialAccessPolicy.Decide(Win(rel), false, MicrosoftSigner));
    }

    [TestMethod]
    public void L_indexation_Windows_est_toleree_depuis_System32()
    {
        Assert.AreEqual(CredentialDecision.Allow,
            CredentialAccessPolicy.Decide(Win(@"System32\SearchProtocolHost.exe"), false, MicrosoftSigner));
        Assert.AreEqual(CredentialDecision.Stop,
            CredentialAccessPolicy.Decide(@"C:\Temp\SearchProtocolHost.exe", false, MicrosoftSigner), "imitation hors dossier système");
    }

    [TestMethod]
    public void Le_leurre_Chromium_n_est_lisible_par_aucun_navigateur()
    {
        Assert.AreEqual(CredentialDecision.Stop,
            CredentialAccessPolicy.Decide(@"C:\Program Files\Google\Chrome\Application\chrome.exe", true, Google));
        Assert.AreEqual(CredentialDecision.Allow,
            CredentialAccessPolicy.Decide(Win(@"System32\SearchIndexer.exe"), true, MicrosoftSigner));
    }

    // ---------- Inventaire et leurre (faux profil Windows en dossier temporaire) ----------

    private static string FakeProfile()
    {
        string root = Path.Combine(Path.GetTempPath(), "cg_profile_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, @"AppData\Local"));
        Directory.CreateDirectory(Path.Combine(root, @"AppData\Roaming"));
        return root;
    }

    private static void Touch(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "x");
    }

    [TestMethod]
    public void L_inventaire_trouve_les_fichiers_sensibles_de_chaque_navigateur()
    {
        string root = FakeProfile();
        try
        {
            string chrome = Path.Combine(root, @"AppData\Local\Google\Chrome\User Data");
            Touch(Path.Combine(chrome, "Local State"));
            Touch(Path.Combine(chrome, @"Default\Login Data"));
            Touch(Path.Combine(chrome, @"Profile 2\Network\Cookies"));
            Touch(Path.Combine(chrome, @"Default\History"));           // non sensible : ignoré
            Touch(Path.Combine(chrome, @"Guest Profile\Login Data"));   // pas un profil utilisateur : ignoré
            Touch(Path.Combine(root, @"AppData\Roaming\Mozilla\Firefox\Profiles\ab12.default\logins.json"));

            var files = CredentialTargets.Enumerate(root);
            CollectionAssert.AreEquivalent(
                new[] { "Local State", "Login Data", "Cookies", "logins.json" },
                files.Select(f => Path.GetFileName(f.Path)).ToArray());
            Assert.IsTrue(files.All(f => !f.Honeypot));
            Assert.AreEqual(1, files.Count(f => f.Browser == "Firefox"));
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    [TestMethod]
    public void Le_leurre_est_cree_inventorie_puis_retire()
    {
        string root = FakeProfile();
        try
        {
            string? honeypot = CredentialTargets.EnsureHoneypot(root);
            Assert.IsNotNull(honeypot);
            Assert.IsTrue(CredentialTargets.IsHoneypot(honeypot));

            var files = CredentialTargets.Enumerate(root);
            Assert.IsTrue(files.Any(f => f.Honeypot && Path.GetFileName(f.Path) == "Login Data"));

            CredentialTargets.RemoveHoneypot(root);
            Assert.IsFalse(Directory.Exists(Path.Combine(root, @"AppData\Local\Chromium")));
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    [TestMethod]
    public void Un_vrai_Chromium_installe_n_est_jamais_touche()
    {
        string root = FakeProfile();
        try
        {
            string real = Path.Combine(root, @"AppData\Local\Chromium\User Data");
            Touch(Path.Combine(real, "Local State")); // vrai profil : pas de marqueur

            Assert.IsNull(CredentialTargets.EnsureHoneypot(root));
            CredentialTargets.RemoveHoneypot(root);
            Assert.IsTrue(File.Exists(Path.Combine(real, "Local State")), "le vrai profil ne doit pas être supprimé");
            Assert.AreEqual("x", File.ReadAllText(Path.Combine(real, "Local State")));
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
}
