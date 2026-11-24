// DÉMO — INOFFENSIF : spécimen 04 (simulateur BadUSB / HID).
// Ouvre SA PROPRE fenêtre de test (zone de texte, équivalent d'un bloc-notes
// de test) et y injecte des frappes à très haute vitesse via SendInput
// (> 500 caractères/seconde), comme le ferait un périphérique HID malveillant.
// Les frappes ne partent que si la fenêtre de test est bien au premier plan ;
// sinon on s'arrête immédiatement (aucune frappe vers une autre application).
// Kill switch : touche Échap dans la fenêtre, ou fermeture de la fenêtre.
using System.Runtime.InteropServices;

ApplicationConfiguration.Initialize();
var texte = new TextBox { Multiline = true, Dock = DockStyle.Fill };
var form = new Form { Text = "CoreGuard DEMO - BadUSB (inoffensif)", Width = 700, Height = 400 };
form.Controls.Add(texte);
bool arret = false;
form.KeyPreview = true;
form.KeyDown += (_, e) => { if (e.KeyCode == Keys.Escape) arret = true; };
form.FormClosing += (_, _) => arret = true;

form.Shown += async (_, _) =>
{
    form.Activate();
    texte.Focus();
    await Task.Delay(1500);
    const string charge = "DEMO-INOFFENSIF ";   // texte factice
    const int total = 2000;                      // caractères injectés
    var debut = DateTime.UtcNow;
    int envoyes = 0;
    while (envoyes < total && !arret)
    {
        // Garde-fou : on n'injecte QUE si notre fenêtre est au premier plan
        if (Native.GetForegroundWindow() != form.Handle) { arret = true; break; }
        foreach (char c in charge) { Native.Frappe(c); envoyes++; }
        await Task.Delay(10);                    // ~1500 car/s
    }
    var duree = (DateTime.UtcNow - debut).TotalSeconds;
    form.Text = $"DEMO terminee : {envoyes} car. en {duree:F2}s (~{envoyes / Math.Max(duree, 0.001):F0} cps)";
};
Application.Run(form);

static class Native
{
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", SetLastError = true)]
    static extern uint SendInput(uint n, INPUT[] entrees, int taille);

    // Union INPUT : on réserve la taille de MOUSEINPUT (la plus grande)
    [StructLayout(LayoutKind.Sequential)]
    struct INPUT { public uint type; public KEYBDINPUT ki; public long pad; }
    [StructLayout(LayoutKind.Sequential)]
    struct KEYBDINPUT { public ushort vk, scan; public uint flags, time; public IntPtr extra; }

    // Frappe Unicode (KEYEVENTF_UNICODE = 4, KEYEVENTF_KEYUP = 2)
    public static void Frappe(char c)
    {
        var bas = new INPUT { type = 1, ki = new KEYBDINPUT { scan = c, flags = 4 } };
        var haut = new INPUT { type = 1, ki = new KEYBDINPUT { scan = c, flags = 4 | 2 } };
        SendInput(2, new[] { bas, haut }, Marshal.SizeOf<INPUT>());
    }
}
