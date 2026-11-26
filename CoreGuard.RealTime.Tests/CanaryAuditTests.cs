namespace CoreGuard.RealTime.Tests;

[TestClass]
public sealed class CanaryAuditTests
{
    private const string Canary = @"C:\Users\Test\Documents\!00_confidentiel.docx";
    private static readonly DateTime When = new(2026, 11, 26, 10, 0, 0, DateTimeKind.Utc);
    private static bool IsCanary(string p) => string.Equals(p, Canary, StringComparison.OrdinalIgnoreCase);

    private static CanaryAccess? Parse(params object?[] values) => CanaryAuditWatcher.Parse(values, When, IsCanary);

    [TestMethod]
    public void Une_ecriture_sur_un_canari_donne_le_pid_exact()
    {
        var access = Parse(Canary, (ulong)0x1F40, @"C:\Temp\evil.exe", "0x2");
        Assert.IsNotNull(access);
        Assert.AreEqual(0x1F40, access.Pid);
        Assert.AreEqual(@"C:\Temp\evil.exe", access.ProcessName);
    }

    [TestMethod]
    public void Les_champs_hexadecimaux_en_chaine_sont_acceptes()
    {
        var access = Parse(Canary, "0x2a", "x.exe", "0x10000"); // DELETE (renommage)
        Assert.AreEqual(42, access!.Pid);
        Assert.AreEqual(CanaryAuditWatcher.Delete, access.AccessMask);
    }

    [TestMethod]
    public void Une_lecture_n_est_jamais_attribuee()
    {
        Assert.IsNull(Parse(Canary, (ulong)100, "indexeur.exe", "0x1"));      // ReadData
        Assert.IsNull(Parse(Canary, (ulong)100, "explorer.exe", "0x80"));     // ReadAttributes
        Assert.IsNull(Parse(Canary, (ulong)100, "explorer.exe", "0x100"));    // WriteAttributes : non audité
    }

    [TestMethod]
    public void Un_autre_fichier_est_ignore()
    {
        Assert.IsNull(Parse(@"C:\Users\Test\Documents\rapport.docx", (ulong)100, "word.exe", "0x2"));
    }

    [TestMethod]
    public void Les_valeurs_invalides_sont_ignorees()
    {
        Assert.IsNull(Parse(Canary, (ulong)0, "x.exe", "0x2"));
        Assert.IsNull(Parse(Canary, "pas-un-pid", "x.exe", "0x2"));
        Assert.IsNull(Parse(Canary, (ulong)100, "x.exe"));
        Assert.IsNull(Parse(null, (ulong)100, "x.exe", "0x2"));
    }

    [TestMethod]
    [DataRow(0x2u, true)]
    [DataRow(0x4u, true)]
    [DataRow(0x10000u, true)]
    [DataRow(0x10002u, true)]
    [DataRow(0x1u, false)]
    [DataRow(0x20000u, false)]
    public void Masques_d_acces(uint mask, bool write)
    {
        Assert.AreEqual(write, CanaryAuditWatcher.IsWriteAccess(mask));
    }

    [TestMethod]
    public void Sans_privilege_la_pose_de_l_audit_echoue_proprement()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".docx");
        File.WriteAllText(path, "x");
        try
        {
            bool ok = CanaryAuditWatcher.TryEnableAudit(path, out string? error);
            if (Environment.IsPrivilegedProcess) Assert.Inconclusive("Session administrateur : la pose réussit, cas non testé ici.");
            Assert.IsFalse(ok);
            Assert.IsNotNull(error);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void La_lecture_de_la_strategie_ne_leve_pas_d_exception()
    {
        _ = CanaryAuditWatcher.IsFileSystemAuditEnabled(); // null sans droits, sinon vrai/faux
    }
}
