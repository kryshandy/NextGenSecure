using System.Diagnostics;

namespace CoreGuard.Behavior.Tests;

[TestClass]
public sealed class ParanoiaExecutionTests
{
    [TestMethod]
    [DataRow(@"C:\Users\Ana\Downloads\outil.exe", true)]
    [DataRow(@"C:\Users\Ana\AppData\Local\Temp\x\payload.exe", true)]
    [DataRow(@"C:\Users\Ana\AppData\Roaming\Updater\upd.exe", true)]
    [DataRow(@"C:\Users\Public\a.exe", true)]
    [DataRow(@"C:\Program Files\Editeur\app.exe", false)]
    [DataRow(@"C:\Windows\System32\notepad.exe", false)]
    [DataRow(@"C:\Users\Ana\AppData\Local\Programs\Code\Code.exe", false)]
    [DataRow(null, false)]
    public void Dossiers_ecrivables_par_l_utilisateur(string? path, bool expected) =>
        Assert.AreEqual(expected, UserDirExecutionPolicy.IsUserWritable(path));

    [TestMethod]
    public void Signe_autorise_non_signe_bloque()
    {
        Assert.IsFalse(UserDirExecutionPolicy.ShouldBlock(@"C:\Users\Ana\Downloads\setup.exe", trustedSignature: true));
        Assert.IsTrue(UserDirExecutionPolicy.ShouldBlock(@"C:\Users\Ana\Downloads\setup.exe", trustedSignature: false));
        Assert.IsFalse(UserDirExecutionPolicy.ShouldBlock(@"C:\Program Files\x\x.exe", trustedSignature: false));
    }

    [TestMethod]
    public void Garde_arrete_seulement_ce_qui_doit_l_etre_et_une_seule_fois()
    {
        var images = new Dictionary<int, string>
        {
            [101] = @"C:\Users\Ana\Downloads\malware.exe",
            [102] = @"C:\Users\Ana\Downloads\installeur-signe.exe",
            [103] = @"C:\Program Files\App\app.exe"
        };
        var killed = new List<int>();
        using var guard = new UserDirExecutionGuard(p => p.EndsWith("installeur-signe.exe"), pid => { killed.Add(pid); return true; },
            pid => images.GetValueOrDefault(pid));
        var blocked = new List<BlockedExecution>();
        guard.Blocked += blocked.Add;

        guard.OnProcessStarted(101);
        guard.OnProcessStarted(102);
        guard.OnProcessStarted(103);
        guard.OnProcessStarted(101); // déjà vu

        CollectionAssert.AreEqual(new[] { 101 }, killed);
        Assert.HasCount(1, blocked);
        Assert.IsTrue(blocked[0].Terminated);
        Assert.AreEqual(1, guard.BlockedCount);
    }

    [TestMethod]
    public void Vrai_processus_non_signe_lance_depuis_TEMP_est_arrete_par_la_scrutation()
    {
        // Copie de ping.exe (signature catalogue Windows, donc « non signé » hors de System32 pour ce test) dans %TEMP%
        string dir = Path.Combine(Path.GetTempPath(), "cg-paranoia-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(dir);
        string exe = Path.Combine(dir, "demo-paranoia.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "PING.EXE"), exe);
        using var guard = new UserDirExecutionGuard(_ => false, pid =>
        {
            using var p = Process.GetProcessById(pid);
            p.Kill();
            return true;
        }, pid =>
        {
            try { using var p = Process.GetProcessById(pid); return p.MainModule?.FileName; } catch { return null; }
        });
        var blocked = new List<BlockedExecution>();
        guard.Blocked += b => { lock (blocked) blocked.Add(b); };
        guard.StartPolling(TimeSpan.FromMilliseconds(200));

        using var started = Process.Start(new ProcessStartInfo(exe, "-n 30 127.0.0.1") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
        try
        {
            Assert.IsTrue(started.WaitForExit(5000), "le processus lancé depuis %TEMP% doit être arrêté");
            lock (blocked) Assert.IsTrue(blocked.Any(b => b.Pid == started.Id));
        }
        finally
        {
            if (!started.HasExited) started.Kill();
            guard.Dispose();
            started.WaitForExit(2000);
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }
}
