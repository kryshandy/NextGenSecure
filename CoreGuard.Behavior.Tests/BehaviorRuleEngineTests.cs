namespace CoreGuard.Behavior.Tests;

[TestClass]
public class BehaviorRuleEngineTests
{
    private static readonly DateTime Now = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static ProcessEvent Ev(int pid, int ppid, string image, string cmd = "") =>
        new(pid, ppid, image, cmd, Now);

    private static IReadOnlyList<BehaviorAlert> Spawn(string parent, string child, string cmd)
    {
        var e = new BehaviorRuleEngine();
        e.Evaluate(Ev(100, 1, parent));
        return e.Evaluate(Ev(200, 100, child, cmd));
    }

    // ---------- Office -> shell ----------

    [TestMethod]
    [DataRow("winword.exe", "powershell.exe")]
    [DataRow("EXCEL.EXE", "cmd.exe")]
    [DataRow("outlook.exe", "wscript.exe")]
    [DataRow(@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    [DataRow("powerpnt.exe", "pwsh.exe")]
    [DataRow("excel.exe", "cscript.exe")]
    [DataRow("excel.exe", "mshta.exe")]
    public void OfficeSpawnsShell_Alerts(string parent, string child)
    {
        var alerts = Spawn(parent, child, "/c whoami");
        Assert.HasCount(1, alerts);
        Assert.AreEqual(BehaviorRuleEngine.RuleOfficeSpawn, alerts[0].Rule);
        Assert.AreEqual(BehaviorRuleEngine.SeverityOfficeSpawn, alerts[0].Severity);
        Assert.AreEqual(200, alerts[0].Pid);
    }

    [TestMethod]
    [DataRow("powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")]
    [DataRow("powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")]
    [DataRow("powershell.exe -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")]
    [DataRow("powershell.exe /enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")]
    public void OfficeSpawnsShell_WithEncodedArg_HigherSeverity(string cmd)
    {
        var alerts = Spawn("winword.exe", "powershell.exe", cmd);
        Assert.HasCount(1, alerts);
        Assert.AreEqual(BehaviorRuleEngine.SeverityOfficeSpawnEncoded, alerts[0].Severity);
        StringAssert.Contains(alerts[0].Detail, "Base64");
    }

    [TestMethod]
    public void OfficeSpawnsShell_LongBase64BlobWithoutSwitch_IsEncoded()
    {
        string blob = new('A', 120);
        var alerts = Spawn("excel.exe", "cmd.exe", "/c echo " + blob);
        Assert.AreEqual(BehaviorRuleEngine.SeverityOfficeSpawnEncoded, alerts[0].Severity);
    }

    [TestMethod]
    public void OfficeSpawnsShell_ShortEncSwitchValue_NotEncoded()
    {
        var alerts = Spawn("winword.exe", "powershell.exe", "-enc abc");
        Assert.AreEqual(BehaviorRuleEngine.SeverityOfficeSpawn, alerts[0].Severity);
    }

    [TestMethod]
    [DataRow("explorer.exe", "powershell.exe")]
    [DataRow("winword.exe", "notepad.exe")]
    [DataRow("winword.exe", "chrome.exe")]
    [DataRow("cmd.exe", "powershell.exe")]
    public void NonOfficeOrNonShell_NoAlert(string parent, string child)
    {
        Assert.IsEmpty(Spawn(parent, child, "-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"));
    }

    [TestMethod]
    public void UnknownParent_NoAlert()
    {
        var e = new BehaviorRuleEngine();
        Assert.IsEmpty(e.Evaluate(Ev(200, 999, "powershell.exe", "-enc AAAAAAAAAAAAAAAAAAAA")));
    }

    [TestMethod]
    public void ParentPidReuse_UsesLatestImage()
    {
        var e = new BehaviorRuleEngine();
        e.Evaluate(Ev(100, 1, "winword.exe"));
        e.Evaluate(Ev(100, 1, "notepad.exe")); // pid réutilisé
        Assert.IsEmpty(e.Evaluate(Ev(200, 100, "powershell.exe")));
    }

    // ---------- Shadow copies ----------

    [TestMethod]
    [DataRow("vssadmin.exe", "delete shadows /all /quiet")]
    [DataRow("VSSADMIN.EXE", "Delete Shadows /For=C: /Oldest")]
    [DataRow(@"C:\Windows\System32\vssadmin.exe", "delete   shadows /all")]
    [DataRow("wmic.exe", "shadowcopy delete")]
    [DataRow("wmic.exe", "SHADOWCOPY WHERE ID='x' DELETE")]
    [DataRow("diskshadow.exe", "/s script.txt delete shadows all")]
    [DataRow("powershell.exe", "Get-WmiObject Win32_ShadowCopy | ForEach-Object {$_.Delete()}")]
    public void ShadowDelete_MaxSeverity(string image, string cmd)
    {
        var alerts = new BehaviorRuleEngine().Evaluate(Ev(1, 0, image, cmd));
        Assert.HasCount(1, alerts);
        Assert.AreEqual(BehaviorRuleEngine.RuleShadowDelete, alerts[0].Rule);
        Assert.AreEqual(BehaviorRuleEngine.SeverityMax, alerts[0].Severity);
    }

    [TestMethod]
    [DataRow("vssadmin.exe", "list shadows")]
    [DataRow("vssadmin.exe", "list writers")]
    [DataRow("wmic.exe", "shadowcopy list brief")]
    [DataRow("wmic.exe", "os get caption")]
    [DataRow("wmic.exe", "process delete")]
    [DataRow("diskshadow.exe", "/s script.txt")]
    [DataRow("notepad.exe", "delete shadows")]
    [DataRow("powershell.exe", "Get-WmiObject Win32_ShadowCopy")]
    public void ShadowDelete_Negatives(string image, string cmd)
    {
        Assert.IsEmpty(new BehaviorRuleEngine().Evaluate(Ev(1, 0, image, cmd)));
    }

    // ---------- Persistance ----------

    [TestMethod]
    [DataRow("schtasks.exe", "/create /tn evil /tr c:\\x.exe /sc onlogon")]
    [DataRow("SCHTASKS.EXE", "/Create /TN evil")]
    [DataRow("schtasks.exe", "-create -tn evil")]
    [DataRow("sc.exe", "create evilsvc binPath= c:\\x.exe")]
    [DataRow("sc.exe", "\\\\host create evilsvc binPath= c:\\x.exe")]
    [DataRow("reg.exe", @"add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d c:\x.exe")]
    [DataRow("reg.exe", @"ADD ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"" /v x /d c:\x.exe")]
    public void Persistence_Alerts(string image, string cmd)
    {
        var alerts = new BehaviorRuleEngine().Evaluate(Ev(1, 0, image, cmd));
        Assert.HasCount(1, alerts);
        Assert.AreEqual(BehaviorRuleEngine.RulePersistence, alerts[0].Rule);
        Assert.AreEqual(BehaviorRuleEngine.SeverityPersistence, alerts[0].Severity);
    }

    [TestMethod]
    [DataRow("schtasks.exe", "/query /fo list")]
    [DataRow("schtasks.exe", "/delete /tn x /f")]
    [DataRow("sc.exe", "query")]
    [DataRow("sc.exe", "start wuauserv")]
    [DataRow("sc.exe", "qc createx")]
    [DataRow("reg.exe", @"query HKCU\Software\Microsoft\Windows\CurrentVersion\Run")]
    [DataRow("reg.exe", @"add HKCU\Software\Foo /v x /d 1")]
    [DataRow("reg.exe", @"add HKCU\Software\Microsoft\Windows\CurrentVersion\Runner /v x")]
    [DataRow("notepad.exe", "/create")]
    public void Persistence_Negatives(string image, string cmd)
    {
        Assert.IsEmpty(new BehaviorRuleEngine().Evaluate(Ev(1, 0, image, cmd)));
    }

    // ---------- Combinaisons, robustesse, assainissement ----------

    [TestMethod]
    public void OfficeThenPersistence_Cmd_CanRaiseTwoRules()
    {
        var e = new BehaviorRuleEngine();
        e.Evaluate(Ev(10, 1, "winword.exe"));
        e.Evaluate(Ev(20, 10, "cmd.exe"));
        var alerts = e.Evaluate(Ev(30, 20, "schtasks.exe", "/create /tn x /tr y"));
        Assert.HasCount(1, alerts); // parent = cmd, pas Office : seule la persistance
        Assert.AreEqual(BehaviorRuleEngine.RulePersistence, alerts[0].Rule);
    }

    [TestMethod]
    public void Null_And_EmptyInputs_DoNotThrow()
    {
        var e = new BehaviorRuleEngine();
        Assert.IsEmpty(e.Evaluate(null));
        Assert.IsEmpty(e.Evaluate(new ProcessEvent(1, 0, null!, null!, Now)));
        Assert.IsEmpty(e.Evaluate(Ev(2, 0, "", "")));
    }

    [TestMethod]
    public void ControlCharacters_AreStrippedFromDetail()
    {
        var alerts = new BehaviorRuleEngine().Evaluate(Ev(1, 0, "vssadmin.exe", "delete shadows\r\nFAKE LOG LINE\0"));
        Assert.HasCount(1, alerts);
        Assert.DoesNotContain("\r", alerts[0].Detail);
        Assert.DoesNotContain("\n", alerts[0].Detail);
        Assert.DoesNotContain("\0", alerts[0].Detail);
    }

    [TestMethod]
    public void HugeCommandLine_DetailIsBounded()
    {
        string cmd = "delete shadows " + new string('x', 100_000);
        var alerts = new BehaviorRuleEngine().Evaluate(Ev(1, 0, "vssadmin.exe", cmd));
        Assert.HasCount(1, alerts);
        Assert.IsLessThanOrEqualTo(512, alerts[0].Detail.Length);
    }

    [TestMethod]
    public void ManyProcesses_TrackingIsBounded_AndStillWorks()
    {
        var e = new BehaviorRuleEngine();
        for (int i = 1000; i < 1000 + 10_000; i++) e.Evaluate(Ev(i, 1, "notepad.exe"));
        e.Evaluate(Ev(50, 1, "winword.exe"));
        Assert.HasCount(1, e.Evaluate(Ev(51, 50, "powershell.exe")));
    }

    [TestMethod]
    public void Evaluate_IsThreadSafe()
    {
        var e = new BehaviorRuleEngine();
        Parallel.For(0, 2000, i => e.Evaluate(Ev(i + 10, i + 9, "powershell.exe", "-enc AAAAAAAAAAAAAAAAAAAA")));
    }

    [TestMethod]
    public void NormalizeImage_HandlesPathsQuotesAndCase()
    {
        Assert.AreEqual("winword", BehaviorRuleEngine.NormalizeImage("\"C:\\Office\\WINWORD.EXE\""));
        Assert.AreEqual("cmd", BehaviorRuleEngine.NormalizeImage("/usr/bin/CMD"));
        Assert.AreEqual("", BehaviorRuleEngine.NormalizeImage(null));
    }
}
