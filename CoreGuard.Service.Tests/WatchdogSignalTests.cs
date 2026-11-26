using System.Security.Cryptography;
using CoreGuard.Service;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace CoreGuard.Service.Tests;

[TestClass]
public sealed class WatchdogSignalTests
{
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);
    private static readonly DateTimeOffset Now = new(2026, 11, 26, 10, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void Un_signal_signe_est_accepte()
    {
        Assert.IsTrue(WatchdogSignal.Verify(Key, WatchdogSignal.Sign(Key, Now), Now));
    }

    [TestMethod]
    public void Un_signal_signe_avec_une_autre_cle_est_refuse()
    {
        string forged = WatchdogSignal.Sign(RandomNumberGenerator.GetBytes(32), Now);
        Assert.IsFalse(WatchdogSignal.Verify(Key, forged, Now));
    }

    [TestMethod]
    public void Un_signal_trop_ancien_est_refuse()
    {
        string old = WatchdogSignal.Sign(Key, Now - WatchdogSignal.MaxSkew - TimeSpan.FromSeconds(1));
        Assert.IsFalse(WatchdogSignal.Verify(Key, old, Now));
    }

    [TestMethod]
    public void Un_horodatage_modifie_invalide_la_signature()
    {
        string[] parts = WatchdogSignal.Sign(Key, Now).Split(' ');
        string tampered = $"{parts[0]} {long.Parse(parts[1]) + 1} {parts[2]}";
        Assert.IsFalse(WatchdogSignal.Verify(Key, tampered, Now));
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("STOP")]
    [DataRow("KILL 1 2")]
    [DataRow("STOP abc def")]
    public void Les_lignes_invalides_sont_refusees(string? line)
    {
        Assert.IsFalse(WatchdogSignal.Verify(Key, line, Now));
    }
}
