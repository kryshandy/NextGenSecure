using CoreGuard.Service;

namespace CoreGuard.Service.Tests;

[TestClass]
public sealed class UserProfilesTests
{
    private const string Profile = @"C:\Users\Alice";

    [TestMethod]
    public void UserProfile_vise_le_profil_de_l_utilisateur_et_non_celui_du_service()
    {
        Assert.AreEqual(@"C:\Users\Alice\Documents", UserProfiles.ExpandShellFolder(@"%USERPROFILE%\Documents", Profile));
        Assert.AreEqual(@"C:\Users\Alice\Desktop", UserProfiles.ExpandShellFolder(@"%userprofile%\Desktop\", Profile));
    }

    [TestMethod]
    public void Un_dossier_redirige_absolu_est_conserve()
    {
        Assert.AreEqual(@"D:\Partage\Alice\Images", UserProfiles.ExpandShellFolder(@"D:\Partage\Alice\Images", Profile));
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    [DataRow(@"Documents")]
    public void Un_chemin_relatif_ou_vide_est_refuse(string raw)
    {
        Assert.IsNull(UserProfiles.ExpandShellFolder(raw, Profile));
    }

    [TestMethod]
    public void L_enumeration_reelle_ne_renvoie_que_des_dossiers_existants()
    {
        var folders = UserProfiles.CanaryFolders();
        Assert.IsTrue(folders.All(Directory.Exists));
        Assert.AreEqual(folders.Count, folders.Distinct(StringComparer.OrdinalIgnoreCase).Count(), "pas de doublon");
    }
}
