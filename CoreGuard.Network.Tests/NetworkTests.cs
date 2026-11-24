using System.Buffers.Binary;
using System.Net;
using CoreGuard.Network;

namespace CoreGuard.Network.Tests;

[TestClass]
public class NetworkTests
{
    private static void Int(List<byte> b, int v) { var t = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(t, v); b.AddRange(t); }
    private static void PortNet(List<byte> b, int port) { b.Add((byte)(port >> 8)); b.Add((byte)port); b.Add(0); b.Add(0); }

    [TestMethod]
    public void ParseTcp4_MappeLigne()
    {
        var b = new List<byte>();
        Int(b, 1);
        Int(b, 5); // ESTABLISHED
        b.AddRange(IPAddress.Parse("192.168.1.10").GetAddressBytes()); PortNet(b, 50000);
        b.AddRange(IPAddress.Parse("93.184.216.34").GetAddressBytes()); PortNet(b, 443);
        Int(b, 1234);

        var c = TcpTableParser.ParseTcp(b.ToArray(), false, pid => pid == 1234 ? "demo" : null).Single();
        Assert.AreEqual("TCP", c.Protocol);
        Assert.AreEqual("192.168.1.10", c.LocalAddress);
        Assert.AreEqual(50000, c.LocalPort);
        Assert.AreEqual("93.184.216.34", c.RemoteAddress);
        Assert.AreEqual(443, c.RemotePort);
        Assert.AreEqual("ESTABLISHED", c.State);
        Assert.AreEqual(1234, c.Pid);
        Assert.AreEqual("demo", c.ProcessName);
    }

    [TestMethod]
    public void ParseTcp6_MappeLigne()
    {
        var b = new List<byte>();
        Int(b, 1);
        b.AddRange(IPAddress.IPv6Loopback.GetAddressBytes()); Int(b, 0); PortNet(b, 8080);
        b.AddRange(new byte[16]); Int(b, 0); PortNet(b, 0);
        Int(b, 2); // LISTEN
        Int(b, 42);

        var c = TcpTableParser.ParseTcp(b.ToArray(), true).Single();
        Assert.AreEqual("TCP6", c.Protocol);
        Assert.AreEqual("::1", c.LocalAddress);
        Assert.AreEqual(8080, c.LocalPort);
        Assert.AreEqual("LISTEN", c.State);
        Assert.AreEqual(42, c.Pid);
        Assert.IsNull(c.ProcessName);
    }

    [TestMethod]
    public void ParseUdp4_PasDePairDistant()
    {
        var b = new List<byte>();
        Int(b, 1);
        b.AddRange(IPAddress.Any.GetAddressBytes()); PortNet(b, 53); Int(b, 7);
        var c = TcpTableParser.ParseUdp(b.ToArray(), false).Single();
        Assert.AreEqual("UDP", c.Protocol);
        Assert.AreEqual(53, c.LocalPort);
        Assert.IsNull(c.RemoteAddress);
        Assert.IsNull(c.RemotePort);
    }

    [TestMethod]
    public void ParseUdp6_MappeLigne()
    {
        var b = new List<byte>();
        Int(b, 1);
        b.AddRange(IPAddress.IPv6Any.GetAddressBytes()); Int(b, 0); PortNet(b, 5353); Int(b, 9);
        var c = TcpTableParser.ParseUdp(b.ToArray(), true).Single();
        Assert.AreEqual("UDP6", c.Protocol);
        Assert.AreEqual(5353, c.LocalPort);
        Assert.AreEqual(9, c.Pid);
    }

    [TestMethod]
    public void Parse_TamponTronqueOuVide_NeCrashePas()
    {
        Assert.AreEqual(0, TcpTableParser.ParseTcp([], false).Count);
        var b = new List<byte>(); Int(b, 50); b.AddRange(new byte[30]); // annonce 50 lignes, 1 seule complète
        Assert.AreEqual(1, TcpTableParser.ParseTcp(b.ToArray(), false).Count);
    }

    [TestMethod]
    public void Parse_ResolverQuiLeve_DonneNull()
    {
        var b = new List<byte>(); Int(b, 1); b.AddRange(IPAddress.Any.GetAddressBytes()); PortNet(b, 1); Int(b, 3);
        var c = TcpTableParser.ParseUdp(b.ToArray(), false, _ => throw new InvalidOperationException()).Single();
        Assert.IsNull(c.ProcessName);
    }

    [TestMethod]
    public void StateName_Inconnu() => Assert.AreEqual("UNKNOWN(99)", TcpTableParser.StateName(99));

    [TestMethod]
    public void RuleNaming_AjouteLePrefixUneSeuleFois()
    {
        Assert.AreEqual("CoreGuard - Foo", RuleNaming.ForRule("Foo"));
        Assert.AreEqual("CoreGuard - Foo", RuleNaming.ForRule("CoreGuard - Foo"));
        Assert.AreEqual("CoreGuard - Block evil.exe", RuleNaming.ForApplication(@"C:\x\evil.exe"));
        Assert.AreEqual("CoreGuard - Block TCP port 445", RuleNaming.ForPort(445, "tcp"));
    }

    [TestMethod]
    public void RuleNaming_Valide()
    {
        Assert.ThrowsExactly<ArgumentException>(() => RuleNaming.ForRule("  "));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RuleNaming.ValidatePort(70000));
        Assert.AreEqual(17, RuleNaming.ProtocolNumber("udp"));
        Assert.ThrowsExactly<ArgumentException>(() => RuleNaming.ProtocolNumber("icmp"));
        Assert.AreEqual("CoreGuard - ab", RuleNaming.ForRule("a|b"));
    }

    [TestMethod]
    public void PortInspector_NeCrashePas()
    {
        Assert.IsNotNull(PortInspector.GetConnections());
    }
}
