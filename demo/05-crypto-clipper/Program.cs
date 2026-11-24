// DÉMO — INOFFENSIF : spécimen 05 (crypto-clipper simulé).
// Surveille le presse-papiers ; si une FAUSSE adresse BTC de démonstration
// apparaît, la remplace par une autre FAUSSE adresse. Aucune adresse réelle,
// aucun réseau, aucun portefeuille. Le programme place lui-même la fausse
// adresse « victime » dans le presse-papiers au démarrage.
// Kill switch : Ctrl+C, ou arrêt automatique après 60 s.
using System.Windows.Forms;

internal static class Programme
{
    const string AdresseVictime = "1DemoVictimeDemoVictimeDemoVictimeXX"; // FAUSSE
    const string AdresseClipper = "1DemoClipperDemoClipperDemoClipperYY"; // FAUSSE

    [STAThread]
    static void Main()
    {
        Console.WriteLine("DEMO INOFFENSIF - clipper simule (60 s max, Ctrl+C pour arreter).");
        Clipboard.SetText(AdresseVictime);
        Console.WriteLine($"Presse-papiers initialise avec la fausse adresse : {AdresseVictime}");

        var fin = DateTime.UtcNow.AddSeconds(60);
        bool arret = false;
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; arret = true; };

        while (!arret && DateTime.UtcNow < fin)
        {
            try
            {
                if (Clipboard.ContainsText() && Clipboard.GetText().Trim() == AdresseVictime)
                {
                    Clipboard.SetText(AdresseClipper);
                    Console.WriteLine($"Remplacement simule -> {AdresseClipper}");
                }
            }
            catch (System.Runtime.InteropServices.ExternalException) { /* presse-papiers occupé */ }
            Thread.Sleep(200);
        }
        Console.WriteLine("Arret. Rien a nettoyer (le presse-papiers contient une fausse valeur).");
    }
}
