using CoreGuard.Privacy;

namespace CoreGuard.Privacy.Tests;

[TestClass]
public class ClipboardAnalysisTests
{
    [TestMethod]
    [DataRow("sk-abcdefghijklmnopqrstuvwxyz123456")]
    [DataRow("AKIAIOSFODNN7EXAMPLE")]
    [DataRow("4111 1111 1111 1111")]
    [DataRow("4111-1111-1111-1111")]
    [DataRow("Tr0ub4dor&3xyzQ!")]
    [DataRow("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")]
    public void IsSecret_Vrai(string s) => Assert.IsTrue(ClipboardAnalysis.IsSecret(s));

    [TestMethod]
    [DataRow("")]
    [DataRow(null)]
    [DataRow("bonjour tout le monde")]
    [DataRow("4111 1111 1111 1112")]      // Luhn invalide
    [DataRow("motdepasse")]               // faible
    [DataRow("https://example.com/page")]
    public void IsSecret_Faux(string? s) => Assert.IsFalse(ClipboardAnalysis.IsSecret(s));

    [TestMethod]
    public void Adresse_Eth() =>
        Assert.AreEqual(CryptoKind.Ethereum, ClipboardAnalysis.DetectCryptoAddress("0x52908400098527886E0F7030069857D2E4169EE7"));

    [TestMethod]
    [DataRow("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")]
    [DataRow("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")]
    public void Adresse_Btc(string a) => Assert.AreEqual(CryptoKind.Bitcoin, ClipboardAnalysis.DetectCryptoAddress(a));

    [TestMethod]
    public void Adresse_Aucune() => Assert.AreEqual(CryptoKind.None, ClipboardAnalysis.DetectCryptoAddress("hello"));

    [TestMethod]
    public void AddressSwap_Detecte()
    {
        Assert.IsTrue(ClipboardAnalysis.IsAddressSwap("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "0x52908400098527886E0F7030069857D2E4169EE7"));
        Assert.IsFalse(ClipboardAnalysis.IsAddressSwap("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        Assert.IsFalse(ClipboardAnalysis.IsAddressSwap("texte", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
    }

    [TestMethod]
    public void DelaiSuspect()
    {
        Assert.IsTrue(ClipboardAnalysis.IsSuspiciousModification(TimeSpan.FromMilliseconds(50), false));
        Assert.IsFalse(ClipboardAnalysis.IsSuspiciousModification(TimeSpan.FromMilliseconds(50), true));
        Assert.IsFalse(ClipboardAnalysis.IsSuspiciousModification(TimeSpan.FromMilliseconds(200), false));
        Assert.IsFalse(ClipboardAnalysis.IsSuspiciousModification(TimeSpan.FromSeconds(5), false));
    }
}

[TestClass]
public class ParanoiaModeTests
{
    [TestMethod]
    public void EtatInitial_Desactive()
    {
        var p = new ParanoiaMode();
        Assert.IsFalse(p.IsEnabled);
        Assert.AreEqual(HardeningPolicy.Off, p.CurrentPolicy);
    }

    [TestMethod]
    public void Activation_LeveEvenementEtPolitique()
    {
        var p = new ParanoiaMode(); HardeningPolicy? got = null; int n = 0;
        p.StateChanged += (_, pol) => { got = pol; n++; };
        Assert.IsTrue(p.SetEnabled(true));
        Assert.AreEqual(1, n);
        Assert.AreEqual(HardeningPolicy.Paranoid, got);
        Assert.IsTrue(got!.BlockNewUsb && got.StrictFirewall && got.BlockExecFromUserDirs);
    }

    [TestMethod]
    public void Idempotent_PasDEvenementSiInchange()
    {
        var p = new ParanoiaMode(); int n = 0;
        p.StateChanged += (_, _) => n++;
        Assert.IsFalse(p.SetEnabled(false));
        p.SetEnabled(true);
        Assert.IsFalse(p.SetEnabled(true));
        Assert.AreEqual(1, n);
    }

    [TestMethod]
    public void Toggle_Alterne()
    {
        var p = new ParanoiaMode();
        Assert.IsTrue(p.Toggle());
        Assert.IsFalse(p.Toggle());
        Assert.AreEqual(HardeningPolicy.Off, p.CurrentPolicy);
    }
}

[TestClass]
public class SensorMonitorPureTests
{
    [TestMethod]
    public void IsInUse()
    {
        Assert.IsTrue(SensorMonitor.IsInUse(10, 0));
        Assert.IsFalse(SensorMonitor.IsInUse(10, 20));
        Assert.IsFalse(SensorMonitor.IsInUse(0, 0));
    }

    [TestMethod]
    public void DecodeProcessName() =>
        Assert.AreEqual(@"C:\app\x.exe", SensorMonitor.DecodeProcessName("C:#app#x.exe"));
}
