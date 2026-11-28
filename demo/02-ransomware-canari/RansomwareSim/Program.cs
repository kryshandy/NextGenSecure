// DÉMO — INOFFENSIF : spécimen 02 compilé (ransomware simulé, couche « leurres + audit »).
//
// Pourquoi une version compilée ? Le script PowerShell 02 est arrêté AVANT de s'exécuter par le fournisseur AMSI de
// CoreGuard (1re couche). Un vrai ransomware est le plus souvent un exécutable, qu'AMSI n'inspecte pas : c'est la
// 2e couche qu'on démontre ici. Le programme :
//  1. « chiffre » SES PROPRES fichiers factices (Documents\CoreGuardDemo, renommés en .coreguard-demo) ;
//  2. écrit dans les fichiers LEURRES de CoreGuard (liste blanche stricte des noms exacts des canaris, racine de
//     Documents, Bureau et Images) : jamais un autre fichier. CoreGuard restaure les leurres aussitôt ;
//  3. n'exécute JAMAIS vssadmin (simple affichage).
// Attendu avec le service installé : arrêt du processus dès le premier leurre (audit NTFS, PID exact), code 0xC0DE0001.
// Kill switch : créer Documents\CoreGuardDemo\STOP.
using System.Text;

string[] canaris = ["!00_confidentiel.docx", "_zz_confidentiel.docx", "~000_backup.xlsx", "!!_comptes_2024.xlsx", "_00_mots_de_passe.txt"];
string documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
string demo = Path.Combine(documents, "CoreGuardDemo");
string stop = Path.Combine(demo, "STOP");
Directory.CreateDirectory(demo);

string lot = DateTime.Now.ToString("yyyyMMdd-HHmmss");
for (int i = 1; i <= 5; i++)
{
    string f = Path.Combine(demo, $"document_factice_{lot}_{i}.txt");
    File.WriteAllText(f, $"DEMO - INOFFENSIF : contenu factice {i}\r\nDEMO-INOFFENSIF");
    File.Move(f, f + ".coreguard-demo");
}
Console.WriteLine($"[1/3] 5 fichiers factices « chiffrés » dans {demo}");

int touches = 0;
foreach (string dossier in new[] { documents, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Environment.GetFolderPath(Environment.SpecialFolder.MyPictures) })
{
    foreach (string nom in canaris)
    {
        string chemin = Path.Combine(dossier, nom);
        if (!File.Exists(chemin)) continue;
        if (File.Exists(stop)) { Console.WriteLine("Kill switch STOP détecté : arrêt."); return 0; }
        Console.WriteLine($"[2/3] Écriture dans le leurre {chemin} ...");
        using (var fs = new FileStream(chemin, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            byte[] octets = Encoding.UTF8.GetBytes("DEMO-INOFFENSIF : contenu « chiffré » par le spécimen 02");
            fs.SetLength(0);
            fs.Write(octets);
        }
        touches++;
        Thread.Sleep(1500); // laisse à CoreGuard le temps de réagir avant le leurre suivant
    }
}
Console.WriteLine($"[2/3] {touches} leurre(s) modifié(s) sans arrêt.");
Console.WriteLine("[3/3] WHAT-IF (non exécuté) : vssadmin delete shadows /all /quiet");
return 0;
