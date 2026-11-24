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

        File.WriteAllText(target, "CHIFFRE PAR RANSOMWARE");

        Assert.IsTrue(await WaitAsync(r), "alerte attendue");
        Assert.AreEqual(target, r.Alerts[0].CanaryPath, ignoreCase: true);
        Assert.AreEqual(1234, r.Alerts[0].SuspectPid);

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline && !File.ReadAllBytes(target).SequenceEqual(original))
            await Task.Delay(100);
        CollectionAssert.AreEqual(original, File.ReadAllBytes(target));
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
