namespace CoreGuard.RealTime.Tests;

[TestClass]
public sealed class DownloadGuardTests
{
    [TestMethod]
    public void Marque_du_Web_lue_depuis_le_vrai_flux_NTFS()
    {
        string file = Path.Combine(Path.GetTempPath(), "cg-motw-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(file, [0x4D, 0x5A]);
        try
        {
            Assert.IsNull(MarkOfTheWeb.Read(file), "fichier local : pas de marque");
            MarkOfTheWeb.Write(file, SecurityZone.Internet, "https://files.exemple-telechargement.test/setup.exe",
                "https://exemple-telechargement.test/page");
            var motw = MarkOfTheWeb.Read(file);
            Assert.IsNotNull(motw);
            Assert.AreEqual(SecurityZone.Internet, motw.Zone);
            Assert.IsTrue(motw.FromInternet);
            Assert.AreEqual("files.exemple-telechargement.test", motw.SourceHost);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [TestMethod]
    public void Contenu_invalide_ignore()
    {
        Assert.IsNull(MarkOfTheWeb.Parse("n'importe quoi"));
        Assert.IsNull(MarkOfTheWeb.Parse("[ZoneTransfer]\nZoneId=9"));
        Assert.AreEqual(SecurityZone.Intranet, MarkOfTheWeb.Parse("[ZoneTransfer]\r\nZoneId=1\r\n")!.Zone);
    }

    private static readonly MarkOfTheWeb Internet = new(SecurityZone.Internet, null, "https://site.test/f");

    [TestMethod]
    public void Executable_signe_venu_d_Internet_vert() =>
        Assert.AreEqual(DownloadLevel.Green, DownloadRisk.Assess("setup.exe", Internet, true, "Editeur SA", "Sain", 5).Level);

    [TestMethod]
    public void Executable_non_signe_venu_d_Internet_orange() =>
        Assert.AreEqual(DownloadLevel.Orange, DownloadRisk.Assess("outil.exe", Internet, false, null, "Sain", 10).Level);

    [TestMethod]
    public void Suspect_non_signe_d_Internet_rouge() =>
        Assert.AreEqual(DownloadLevel.Red, DownloadRisk.Assess("facture.js", Internet, false, null, "Suspect", 45).Level);

    [TestMethod]
    public void Malveillant_toujours_rouge() =>
        Assert.AreEqual(DownloadLevel.Red, DownloadRisk.Assess("photo.jpg", null, false, null, "Malveillant", 90).Level);

    [TestMethod]
    public void Site_restreint_rouge() =>
        Assert.AreEqual(DownloadLevel.Red,
            DownloadRisk.Assess("doc.pdf", new MarkOfTheWeb(SecurityZone.Restricted, null, null), false, null, "Sain", 0).Level);

    [TestMethod]
    public void Document_sain_vert_et_macro_orange()
    {
        Assert.AreEqual(DownloadLevel.Green, DownloadRisk.Assess("cours.pdf", Internet, false, null, "Sain", 0).Level);
        Assert.AreEqual(DownloadLevel.Orange, DownloadRisk.Assess("bilan.xlsm", Internet, false, null, "Sain", 0).Level);
    }

    [TestMethod]
    public void Raisons_lisibles()
    {
        var a = DownloadRisk.Assess("outil.exe", Internet, false, null, "Sain", 10);
        CollectionAssert.Contains(a.Reasons.ToList(), "téléchargé depuis Internet (site.test)");
        CollectionAssert.Contains(a.Reasons.ToList(), "non signé");
    }
}
