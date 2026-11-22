using System.Text;
using AntivirusIA.Infrastructure;

namespace AntivirusIA.Tests;

[TestClass]
public sealed class QuarantineServiceTests
{
    private static string NouveauDossier()
    {
        string dossier = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dossier);
        return dossier;
    }

    [TestMethod]
    public async Task Le_fichier_est_deplace_et_chiffre()
    {
        string racine = NouveauDossier();
        try
        {
            string quarantaine = Path.Combine(racine, "quarantaine");
            string fichier = Path.Combine(racine, "suspect.txt");
            await File.WriteAllTextAsync(fichier, "contenu tres reconnaissable");

            var service = new QuarantineService(quarantaine);
            var entree = await service.QuarantineAsync(fichier, "test");

            Assert.IsFalse(File.Exists(fichier));
            Assert.AreEqual(1, service.List().Count);

            byte[] brut = await File.ReadAllBytesAsync(Path.Combine(quarantaine, entree.Id + ".quar"));
            Assert.IsFalse(Encoding.Latin1.GetString(brut).Contains("reconnaissable"));
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }

    [TestMethod]
    public async Task La_restauration_retrouve_le_contenu_d_origine()
    {
        string racine = NouveauDossier();
        try
        {
            string fichier = Path.Combine(racine, "document.txt");
            await File.WriteAllTextAsync(fichier, "contenu a retrouver");

            var service = new QuarantineService(Path.Combine(racine, "quarantaine"));
            var entree = await service.QuarantineAsync(fichier, "test");
            await service.RestoreAsync(entree.Id);

            Assert.AreEqual("contenu a retrouver", await File.ReadAllTextAsync(fichier));
            Assert.AreEqual(0, service.List().Count);
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }

    [TestMethod]
    public async Task La_suppression_efface_l_entree_et_le_fichier_stocke()
    {
        string racine = NouveauDossier();
        try
        {
            string quarantaine = Path.Combine(racine, "quarantaine");
            string fichier = Path.Combine(racine, "a_supprimer.txt");
            await File.WriteAllTextAsync(fichier, "donnees");

            var service = new QuarantineService(quarantaine);
            var entree = await service.QuarantineAsync(fichier, "test");
            await service.DeleteAsync(entree.Id);

            Assert.AreEqual(0, service.List().Count);
            Assert.IsFalse(File.Exists(Path.Combine(quarantaine, entree.Id + ".quar")));
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }

    [TestMethod]
    public async Task L_index_survit_a_un_redemarrage()
    {
        string racine = NouveauDossier();
        try
        {
            string quarantaine = Path.Combine(racine, "quarantaine");
            string fichier = Path.Combine(racine, "persistant.txt");
            await File.WriteAllTextAsync(fichier, "donnees");

            var premier = new QuarantineService(quarantaine);
            await premier.QuarantineAsync(fichier, "test");

            var second = new QuarantineService(quarantaine);
            Assert.AreEqual(1, second.List().Count);
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }
}