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

    private static async Task<(string racine, string quarantaine, QuarantineService service, Guid id, byte[] original)> PreparerAsync(int taille)
    {
        string racine = NouveauDossier();
        string quarantaine = Path.Combine(racine, "quarantaine");
        string fichier = Path.Combine(racine, "donnees.bin");
        byte[] original = System.Security.Cryptography.RandomNumberGenerator.GetBytes(taille);
        await File.WriteAllBytesAsync(fichier, original);
        var service = new QuarantineService(quarantaine);
        var entree = await service.QuarantineAsync(fichier, "test");
        return (racine, quarantaine, service, entree.Id, original);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1024 * 1024)]           // exactement un bloc
    [DataRow(3 * 1024 * 1024 + 17)]  // plusieurs blocs + reste
    public async Task Aller_retour_quelle_que_soit_la_taille(int taille)
    {
        var (racine, _, service, id, original) = await PreparerAsync(taille);
        try
        {
            await service.RestoreAsync(id);
            CollectionAssert.AreEqual(original, await File.ReadAllBytesAsync(Path.Combine(racine, "donnees.bin")));
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }

    [TestMethod]
    public async Task Un_fichier_altere_n_est_pas_restaure()
    {
        var (racine, quarantaine, service, id, _) = await PreparerAsync(4096);
        try
        {
            string stocke = Path.Combine(quarantaine, id + ".quar");
            byte[] brut = await File.ReadAllBytesAsync(stocke);
            brut[100] ^= 0x01; // un seul bit modifié dans le contenu chiffré
            await File.WriteAllBytesAsync(stocke, brut);

            await Assert.ThrowsExactlyAsync<IOException>(() => service.RestoreAsync(id));
            Assert.IsFalse(File.Exists(Path.Combine(racine, "donnees.bin")), "rien ne doit être écrit à l'emplacement d'origine");
            Assert.AreEqual(0, Directory.GetFiles(racine).Length, "aucun fichier temporaire ne doit subsister");
            Assert.AreEqual(1, service.List().Count, "l'entrée reste en quarantaine");
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }

    [TestMethod]
    public async Task Un_fichier_tronque_n_est_pas_restaure()
    {
        var (racine, quarantaine, service, id, _) = await PreparerAsync(2 * 1024 * 1024 + 10);
        try
        {
            string stocke = Path.Combine(quarantaine, id + ".quar");
            byte[] brut = await File.ReadAllBytesAsync(stocke);
            await File.WriteAllBytesAsync(stocke, brut[..(20 + 1024 * 1024 + 16)]); // ne garde que le 1er bloc

            await Assert.ThrowsExactlyAsync<IOException>(() => service.RestoreAsync(id));
            Assert.IsFalse(File.Exists(Path.Combine(racine, "donnees.bin")));
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }

    [TestMethod]
    public async Task La_cle_n_est_pas_stockee_en_clair()
    {
        if (!OperatingSystem.IsWindows()) Assert.Inconclusive("DPAPI : Windows uniquement");
        var (racine, quarantaine, _, _, _) = await PreparerAsync(16);
        try
        {
            byte[] cle = await File.ReadAllBytesAsync(Path.Combine(quarantaine, "quarantine.key"));
            Assert.AreNotEqual(32, cle.Length);
            CollectionAssert.AreEqual("CGK2"u8.ToArray(), cle[..4]);
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }

    [TestMethod]
    public async Task Ancienne_quarantaine_cbc_avec_cle_en_clair_reste_restaurable()
    {
        string racine = NouveauDossier();
        try
        {
            // Reconstitue une quarantaine au format v1 : clé brute de 32 octets + fichier IV|AES-CBC
            string quarantaine = Path.Combine(racine, "quarantaine");
            Directory.CreateDirectory(quarantaine);
            byte[] cle = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            await File.WriteAllBytesAsync(Path.Combine(quarantaine, "quarantine.key"), cle);

            byte[] clair = Encoding.UTF8.GetBytes("ancien contenu en quarantaine");
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.Key = cle;
            aes.GenerateIV();
            byte[] chiffre = aes.EncryptCbc(clair, aes.IV);
            var id = Guid.NewGuid();
            await File.WriteAllBytesAsync(Path.Combine(quarantaine, id + ".quar"), [.. aes.IV, .. chiffre]);

            string origine = Path.Combine(racine, "ancien.txt");
            var entree = new AntivirusIA.Core.Models.QuarantineEntry(id, origine, "v1", DateTime.UtcNow, clair.Length);
            await File.WriteAllTextAsync(Path.Combine(quarantaine, "index.json"),
                System.Text.Json.JsonSerializer.Serialize(new[] { entree }));

            var service = new QuarantineService(quarantaine);
            await service.RestoreAsync(id);

            Assert.AreEqual("ancien contenu en quarantaine", await File.ReadAllTextAsync(origine));
            if (OperatingSystem.IsWindows())
                Assert.AreNotEqual(32, (await File.ReadAllBytesAsync(Path.Combine(quarantaine, "quarantine.key"))).Length,
                    "la clé en clair doit avoir été migrée vers DPAPI");
        }
        finally
        {
            Directory.Delete(racine, true);
        }
    }
}
