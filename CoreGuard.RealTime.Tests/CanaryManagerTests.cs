namespace CoreGuard.RealTime.Tests;

internal sealed class FakeResponder : IThreatResponder
{
    public List<CanaryAlert> Alerts { get; } = [];
    public SemaphoreSlim Signal { get; } = new(0);

    public Task OnCanaryTriggeredAsync(CanaryAlert alert, CancellationToken ct)
    {
        lock (Alerts) Alerts.Add(alert);
        Signal.Release();
        return Task.CompletedTask;
    }

    public Task KillProcessAsync(int pid) => Task.CompletedTask;
    public Task QuarantineAsync(string path, string reason) => Task.CompletedTask;
}

[TestClass]
public sealed class CanaryManagerTests
{
    private string _dir = null!;

    [TestInitialize]
    public void Init()
    {
        _dir = Path.Combine(Path.GetTempPath(), "cg_canary_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    [TestCleanup]
    public void Cleanup()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private static Task<bool> WaitAsync(FakeResponder r) => r.Signal.WaitAsync(TimeSpan.FromSeconds(10));

    private static byte[]? TryRead(string path)
    {
        try { return File.ReadAllBytes(path); }
        catch (IOException) { return null; }
    }

    // Comme un ransomware : ouverture du fichier EXISTANT en écriture (fonctionne aussi sur un fichier caché)
    // (avec quelques essais : l'antivirus ou l'indexeur peut tenir brièvement le fichier qui vient d'être écrit)
    private static void Overwrite(string path, string text)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                fs.SetLength(0);
                fs.Write(System.Text.Encoding.UTF8.GetBytes(text));
                return;
            }
            catch (IOException) when (attempt < 20)
            {
                Thread.Sleep(100);
            }
        }
    }

    [TestMethod]
    public void Les_canaris_sont_caches_et_signales_a_l_ecriture()
    {
        using var m = new CanaryManager(new FakeResponder(), () => null);
        var written = new List<string>();
        m.CanaryWritten += (_, p) => { lock (written) written.Add(p); };

        var created = m.Deploy([_dir]);

        Assert.IsTrue(created.All(p => File.GetAttributes(p).HasFlag(FileAttributes.Hidden)));
        Assert.HasCount(created.Count, written);
        Assert.IsTrue(created.All(m.IsCanary));
        CollectionAssert.Contains(CanaryManager.DefaultCanaryNames, "!00_confidentiel.docx");
    }

    [TestMethod]
    public void Un_second_depot_reecrit_les_canaris_caches()
    {
        using var first = new CanaryManager(new FakeResponder(), () => null);
        first.Deploy([_dir]);
        using var second = new CanaryManager(new FakeResponder(), () => null);
        var again = second.Deploy([_dir]);
        Assert.HasCount(CanaryManager.DefaultCanaryNames.Length, again, "un canari caché existant doit pouvoir être réécrit");
    }

    [TestMethod]
    public void Remove_supprime_aussi_les_canaris_caches()
    {
        using var m = new CanaryManager(new FakeResponder(), () => null);
        var created = m.Deploy([_dir]);
        m.Remove();
        Assert.IsFalse(created.Any(File.Exists));
    }

    [TestMethod]
    public void Deploy_CreatesCanaries_AndSkipsMissingFolders()
    {
        using var m = new CanaryManager(new FakeResponder(), () => null);
        var created = m.Deploy([_dir, Path.Combine(_dir, "inexistant")]);
        Assert.HasCount(CanaryManager.DefaultCanaryNames.Length, created);
        Assert.IsTrue(created.All(File.Exists));
    }

    [TestMethod]
    public async Task Modify_TriggersAlert_AndAutoRestores()
    {
        var r = new FakeResponder();
        using var m = new CanaryManager(r, () => 1234);
        var target = m.Deploy([_dir])[0];
        var original = File.ReadAllBytes(target);
        await Task.Delay(1000); // laisse expirer la fenêtre d'auto-écriture

        Overwrite(target, "CHIFFRE PAR RANSOMWARE");

        Assert.IsTrue(await WaitAsync(r), "alerte attendue");
        Assert.AreEqual(target, r.Alerts[0].CanaryPath, ignoreCase: true);
        Assert.AreEqual(1234, r.Alerts[0].SuspectPid);

        // Lecture tolérante : pendant la restauration, le fichier est momentanément verrouillé en écriture
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline && !(TryRead(target)?.SequenceEqual(original) ?? false))
            await Task.Delay(100);
        CollectionAssert.AreEqual(original, TryRead(target));
    }

    [TestMethod]
    public async Task Delete_TriggersAlert()
    {
        var r = new FakeResponder();
        using var m = new CanaryManager(r, () => null) { AutoRestore = false };
        var target = m.Deploy([_dir])[0];
        await Task.Delay(1000);

        File.Delete(target);

        Assert.IsTrue(await WaitAsync(r));
        Assert.AreEqual("Deleted", r.Alerts[0].OperationType);
    }

    [TestMethod]
    public async Task Restore_RecreatesDeletedCanary_WithOriginalContent()
    {
        using var m = new CanaryManager(new FakeResponder(), () => null) { AutoRestore = false };
        var target = m.Deploy([_dir])[0];
        var original = File.ReadAllBytes(target);
        File.Delete(target);

        Assert.IsTrue(await m.RestoreAsync(target));
        CollectionAssert.AreEqual(original, File.ReadAllBytes(target));
        Assert.IsFalse(await m.RestoreAsync(Path.Combine(_dir, "inconnu.txt")));
    }
}
