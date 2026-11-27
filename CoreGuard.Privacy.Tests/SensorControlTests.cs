using System.Diagnostics;
using CoreGuard.Privacy;

namespace CoreGuard.Privacy.Tests;

[TestClass]
public sealed class SensorControlTests
{
    [TestMethod]
    public void Distingue_application_de_bureau_et_application_du_Store()
    {
        Assert.IsTrue(SensorControl.IsDesktopApp(@"C:\Program Files\Zoom\bin\Zoom.exe"));
        Assert.IsFalse(SensorControl.IsDesktopApp("Microsoft.WindowsCamera_8wekyb3d8bbwe"));
    }

    [TestMethod]
    public void Le_refus_par_application_n_existe_que_pour_le_Store()
    {
        Assert.IsNull(SensorControl.PackagedConsentKey("webcam", @"C:\Apps\spy.exe"));
        StringAssert.EndsWith(SensorControl.PackagedConsentKey("webcam", "Microsoft.WindowsCamera_8wekyb3d8bbwe")!,
            @"ConsentStore\webcam\Microsoft.WindowsCamera_8wekyb3d8bbwe");
        StringAssert.EndsWith(SensorControl.DesktopAppsConsentKey("microphone"), @"ConsentStore\microphone\NonPackaged");
    }

    private static Process StartPing() => Process.Start(new ProcessStartInfo("ping.exe", "-n 60 127.0.0.1")
    {
        CreateNoWindow = true,
        UseShellExecute = false,
        RedirectStandardOutput = true
    })!;

    [TestMethod]
    public void Les_processus_sont_retrouves_par_leur_chemin_exact()
    {
        using var ping = StartPing();
        try
        {
            string path = Path.Combine(Environment.SystemDirectory, "PING.EXE"); // MainModule peut être null juste après le démarrage
            // Juste après son démarrage, le chemin du processus n'est pas toujours lisible : on lui laisse 2 s
            var deadline = DateTime.UtcNow.AddSeconds(2);
            while (!SensorControl.FindProcessesByImage(path).Contains(ping.Id) && DateTime.UtcNow < deadline) Thread.Sleep(50);
            CollectionAssert.Contains(SensorControl.FindProcessesByImage(path).ToList(), ping.Id);
            Assert.AreEqual(0, SensorControl.FindProcessesByImage(@"C:\Ailleurs\PING.EXE").Count, "même nom, autre chemin : ignoré");
        }
        finally
        {
            ping.Kill();
        }
    }

    [TestMethod]
    public void Couper_une_application_de_bureau_arrete_ses_processus()
    {
        using var ping = StartPing();
        string path = Path.Combine(Environment.SystemDirectory, "PING.EXE"); // MainModule peut être null juste après le démarrage
        var killed = new List<int>();

        // Application de bureau : aucune écriture dans le registre, seul l'arrêt des processus est tenté
        var result = SensorControl.Cut(new SensorUsage("webcam", path, true, DateTime.UtcNow), pid =>
        {
            killed.Add(pid);
            if (pid != ping.Id) return false; // n'arrête que le ping de ce test (les autres tests en lancent aussi, en parallèle)
            using var p = Process.GetProcessById(pid);
            p.Kill();
            return true;
        });

        CollectionAssert.Contains(killed, ping.Id);
        Assert.IsGreaterThanOrEqualTo(1, result.ProcessesStopped);
        Assert.IsFalse(result.AccessDenied);
        StringAssert.Contains(result.Message, "applications de bureau");
        Assert.IsTrue(ping.WaitForExit(5000));
    }
}
