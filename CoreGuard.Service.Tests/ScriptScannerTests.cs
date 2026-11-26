using System.Text;
using AntivirusIA.Engines;
using CoreGuard.Ipc;
using CoreGuard.Service;

namespace CoreGuard.Service.Tests;

[TestClass]
public sealed class ScriptScannerTests
{
    private static readonly ScriptScanner Scanner =
        new(new PatternRuleEngine(Path.Combine(AppContext.BaseDirectory, "Data", "rules.json")));

    // PowerShell soumet ses scripts à AMSI en UTF-16LE
    private static AmsiVerdict ScanPowerShell(string script) =>
        Scanner.Evaluate(new AmsiScanRequest("PowerShell_C:\\Windows\\System32\\powershell.exe", null,
            Convert.ToBase64String(Encoding.Unicode.GetBytes(script))));

    // Motifs sensibles reconstitués à l'exécution : la DLL de test ne contient jamais la chaîne complète
    private static string Join(params string[] parts) => string.Concat(parts);

    [TestMethod]
    public void Le_specimen_01_est_bloque()
    {
        string demo = File.ReadAllText(Path.Combine(RepoRoot(), "demo", "01-powershell-amsi", "demo-amsi.ps1"));
        var verdict = ScanPowerShell(demo);
        Assert.IsTrue(verdict.Detected, verdict.Reason);
        StringAssert.Contains(verdict.Reason, "Script-Base64Execution");
    }

    [TestMethod]
    public void Un_script_banal_passe()
    {
        var verdict = ScanPowerShell("Get-ChildItem C:\\Temp | Where-Object Length -gt 1MB | Sort-Object Name");
        Assert.IsFalse(verdict.Detected);
        Assert.AreEqual(0, verdict.Score);
    }

    [TestMethod]
    public void Un_motif_cache_dans_du_Base64_est_trouve()
    {
        // Contournement AMSI encodé en Base64 (UTF-16, comme -EncodedCommand) au sein d'un script anodin
        string hidden = Join("[Ref].Assembly.GetType('System.Management.Automation.Amsi", "Utils').GetField('amsi", "InitFailed')");
        string blob = Convert.ToBase64String(Encoding.Unicode.GetBytes(hidden));
        var verdict = ScanPowerShell($"$x = '{blob}'; Write-Output 'rien'");

        Assert.IsTrue(verdict.Detected, verdict.Reason);
        StringAssert.Contains(verdict.Reason, "Base64 décodé");
    }

    [TestMethod]
    public void Une_suppression_des_cliches_dans_un_script_est_bloquee()
    {
        Assert.IsTrue(ScanPowerShell("Start-Process vssadmin -ArgumentList 'delete shadows /all /quiet'").Detected);
    }

    [TestMethod]
    public void Un_contenu_vide_ou_illisible_passe()
    {
        Assert.IsFalse(Scanner.Evaluate(null).Detected);
        Assert.IsFalse(Scanner.Evaluate(new AmsiScanRequest("x", null, "")).Detected);
        Assert.IsFalse(Scanner.Evaluate(new AmsiScanRequest("x", null, "pas du base64 !")).Detected);
    }

    [TestMethod]
    public void Le_decodage_distingue_utf16_et_utf8()
    {
        Assert.AreEqual("Write-Output 'é'", ScriptScanner.Decode(Encoding.Unicode.GetBytes("Write-Output 'é'")));
        Assert.AreEqual("WScript.Echo \"é\"", ScriptScanner.Decode(Encoding.UTF8.GetBytes("WScript.Echo \"é\"")));
    }

    [TestMethod]
    public void Les_blobs_binaires_ne_sont_pas_analyses()
    {
        string binary = Convert.ToBase64String(Enumerable.Range(0, 64).Select(i => (byte)(i * 37 % 256)).ToArray());
        Assert.AreEqual(0, ScriptScanner.DecodeBase64Blobs(binary).Count());
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AntivirusIA.slnx"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Racine du dépôt introuvable");
    }
}
