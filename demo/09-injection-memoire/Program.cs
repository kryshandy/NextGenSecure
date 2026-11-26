// DÉMO — INOFFENSIF : spécimen 09 (injection mémoire / « fileless »).
//
// Reproduit la TRACE en mémoire d'un chargement réflectif de DLL, sans rien exécuter :
//  - alloue une zone mémoire privée lisible + modifiable + exécutable (RWX) DANS SON PROPRE PROCESSUS ;
//  - y écrit un faux en-tête d'exécutable (« MZ » … « PE\0\0 ») suivi d'un texte DEMO-INOFFENSIF ;
//  - n'y place AUCUN code, n'appelle jamais cette zone, ne touche à aucun autre processus ;
//  - attend 120 s en affichant qu'il est toujours vivant.
// Attendu avec le service CoreGuard : au prochain scan mémoire (≤ 30 s), CoreGuard repère une image PE hors de
// tout fichier et ARRÊTE ce processus (la fenêtre se ferme ; code de sortie 0xC0DE0001).
// Kill switch : Ctrl+C. Nettoyage : aucun (la mémoire disparaît avec le processus).
using System.Runtime.InteropServices;
using System.Text;

const int size = 64 * 1024;
IntPtr zone = Native.VirtualAlloc(IntPtr.Zero, size, 0x3000 /* MEM_COMMIT|MEM_RESERVE */, 0x40 /* PAGE_EXECUTE_READWRITE */);
if (zone == IntPtr.Zero) { Console.WriteLine("Allocation impossible."); return 1; }

var image = new byte[0x200];
image[0] = (byte)'M'; image[1] = (byte)'Z';
BitConverter.GetBytes(0x80).CopyTo(image, 0x3C);                 // e_lfanew
Encoding.ASCII.GetBytes("PE\0\0").CopyTo(image, 0x80);           // signature PE (en-têtes vides : aucun code)
Encoding.ASCII.GetBytes("CoreGuard DEMO-INOFFENSIF : faux module en memoire, jamais execute").CopyTo(image, 0x100);
Marshal.Copy(image, 0, zone, image.Length);

Console.WriteLine($"[DEMO-INOFFENSIF] Faux module écrit à 0x{zone:X} (RWX, mémoire privée), PID {Environment.ProcessId}.");
Console.WriteLine("CoreGuard doit arrêter ce processus au prochain scan mémoire (30 s maximum).");
for (int s = 0; s <= 120; s += 5)
{
    Console.WriteLine($"  toujours vivant après {s} s…");
    Thread.Sleep(5000);
}
Console.WriteLine("RÉSULTAT : non arrêté. Vérifiez que le service CoreGuard est installé et démarré.");
return 0;

static class Native
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr address, nuint size, uint allocationType, uint protect);
}
