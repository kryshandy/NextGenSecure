using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using CoreGuard.Response;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace CoreGuard.Response.Tests;

[TestClass]
public sealed class UserModeActionProviderTests
{
    // Processus enfant inoffensif qui attend ~60 s : cible de test pour l'arrêt et la suspension
    private static Process StartChild()
    {
        var psi = new ProcessStartInfo("ping.exe", "-n 60 127.0.0.1")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true
        };
        return Process.Start(psi)!;
    }

    private static void Cleanup(Process p)
    {
        try { if (!p.HasExited) p.Kill(); } catch { /* déjà terminé */ }
        p.Dispose();
    }

    [TestMethod]
    public async Task Arrete_un_processus_enfant()
    {
        using var child = StartChild();
        try
        {
            var result = await new UserModeActionProvider().TerminateProcessAsync(child.Id, "test");

            Assert.IsTrue(result.Success, result.Message);
            Assert.IsTrue(child.WaitForExit(5000));
            Assert.AreEqual(unchecked((int)0xC0DE0001), child.ExitCode);
        }
        finally
        {
            Cleanup(child);
        }
    }

    [TestMethod]
    public async Task Refuse_les_processus_systeme_et_soi_meme()
    {
        var provider = new UserModeActionProvider();

        Assert.IsFalse((await provider.TerminateProcessAsync(4, "test")).Success);
        Assert.IsFalse((await provider.TerminateProcessAsync(0, "test")).Success);
        Assert.IsFalse((await provider.TerminateProcessAsync(Environment.ProcessId, "test")).Success);
        Assert.IsFalse((await provider.SuspendProcessAsync(Environment.ProcessId)).Success);
    }

    [TestMethod]
    public void Refuse_les_processus_critiques_par_leur_nom()
    {
        // Vérification pure : aucune action n'est tentée sur ces processus
        var provider = new UserModeActionProvider();
        foreach (string name in new[] { "csrss", "lsass", "winlogon", "services" })
        {
            var p = Process.GetProcessesByName(name).FirstOrDefault();
            if (p is null) continue;
            using (p)
            {
                var refus = provider.CheckTarget(p.Id);
                Assert.IsNotNull(refus, $"{name} doit être refusé");
                Assert.IsFalse(refus.Success);
            }
        }
    }

    [TestMethod]
    public async Task Refuse_un_processus_protege_enregistre()
    {
        using var child = StartChild();
        try
        {
            var provider = new UserModeActionProvider();
            provider.AddProtectedProcess(child.Id);

            Assert.IsFalse((await provider.TerminateProcessAsync(child.Id, "test")).Success);
            Assert.IsFalse(child.HasExited);
        }
        finally
        {
            Cleanup(child);
        }
    }

    [TestMethod]
    public async Task Processus_inexistant_echoue_proprement()
    {
        var result = await new UserModeActionProvider().TerminateProcessAsync(int.MaxValue - 3, "test");
        Assert.IsFalse(result.Success);
    }

    [TestMethod]
    public async Task Suspend_puis_reprend_un_processus()
    {
        using var child = StartChild();
        try
        {
            var provider = new UserModeActionProvider();

            Assert.IsTrue((await provider.SuspendProcessAsync(child.Id)).Success);
            child.Refresh();
            Assert.IsTrue(child.Threads.Cast<ProcessThread>().All(IsSuspended), "tous les threads doivent être gelés");

            Assert.IsTrue((await provider.ResumeProcessAsync(child.Id)).Success);
            child.Refresh();
            Assert.IsFalse(child.Threads.Cast<ProcessThread>().All(IsSuspended));
        }
        finally
        {
            Cleanup(child);
        }
    }

    private static bool IsSuspended(ProcessThread t)
    {
        try { return t.ThreadState == System.Diagnostics.ThreadState.Wait && t.WaitReason == ThreadWaitReason.Suspended; }
        catch (InvalidOperationException) { return true; } // thread terminé entre-temps
    }

    [TestMethod]
    public async Task Un_processus_durci_ne_peut_plus_etre_arrete_par_un_tiers()
    {
        using var child = StartChild();
        try
        {
            var harden = UserModeActionProvider.ProtectProcess(child.Id);
            Assert.IsTrue(harden.Success, harden.Message);

            // Nouvelle ouverture (comme le ferait taskkill) : l'arrêt est refusé
            var kill = await new UserModeActionProvider().TerminateProcessAsync(child.Id, "test");
            Assert.IsFalse(kill.Success, "la DACL durcie doit refuser PROCESS_TERMINATE");
            Assert.IsFalse(child.HasExited);
        }
        finally
        {
            // Le handle obtenu au lancement, antérieur au durcissement, garde tous ses droits : nettoyage possible
            Cleanup(child);
        }
    }

    [TestMethod]
    public async Task Protege_un_fichier_isole()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".quar");
        await File.WriteAllTextAsync(path, "contenu isolé");
        try
        {
            var result = await new UserModeActionProvider().ProtectFileAsync(path);
            Assert.IsTrue(result.Success, result.Message);

            var acl = new FileInfo(path).GetAccessControl();
            Assert.IsTrue(acl.AreAccessRulesProtected, "l'héritage doit être coupé");

            var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
            var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            Assert.IsTrue(rules.Any(r => r.AccessControlType == AccessControlType.Deny
                                         && r.IdentityReference.Equals(everyone)
                                         && r.FileSystemRights.HasFlag(FileSystemRights.ExecuteFile)));

            // L'utilisateur peut toujours lire (restauration) puis supprimer
            Assert.AreEqual("contenu isolé", await File.ReadAllTextAsync(path));
        }
        finally
        {
            File.Delete(path);
        }
        Assert.IsFalse(File.Exists(path));
    }

    [TestMethod]
    public async Task Blocage_reseau_sans_pare_feu_echoue_proprement()
    {
        var result = await new UserModeActionProvider().BlockNetworkAsync(Environment.ProcessId, null);
        Assert.IsFalse(result.Success);
    }

    [TestMethod]
    public async Task Blocage_reseau_resout_le_chemin_de_l_executable()
    {
        using var child = StartChild();
        try
        {
            string? blocked = null;
            var provider = new UserModeActionProvider((_, path) => { blocked = path; return true; });

            var result = await provider.BlockNetworkAsync(child.Id, null);

            Assert.IsTrue(result.Success, result.Message);
            StringAssert.EndsWith(blocked!, "PING.EXE", StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Cleanup(child);
        }
    }
}
