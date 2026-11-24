using System.Buffers.Binary;
using System.Net;

namespace CoreGuard.Network;

/// <summary>
/// Conversion pure octets -> <see cref="Connection"/> des tables IP Helper
/// (MIB_TCPTABLE_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID).
/// Aucune dépendance à l'OS : entièrement testable. Tolère les tampons tronqués/corrompus.
/// </summary>
public static class TcpTableParser
{
    // Tailles des lignes (octets) pour chaque structure native.
    internal const int Tcp4RowSize = 24;
    internal const int Tcp6RowSize = 56;
    internal const int Udp4RowSize = 12;
    internal const int Udp6RowSize = 28;

    /// <summary>Résout un PID en nom de processus (peut renvoyer null).</summary>
    public delegate string? ProcessNameResolver(int pid);

    /// <summary>Parse une table TCP (IPv4 ou IPv6).</summary>
    public static IReadOnlyList<Connection> ParseTcp(ReadOnlySpan<byte> table, bool ipv6, ProcessNameResolver? resolver = null)
    {
        int rowSize = ipv6 ? Tcp6RowSize : Tcp4RowSize;
        var result = new List<Connection>();
        foreach (var row in Rows(table, rowSize))
        {
            string local, remote; int lport, rport, state, pid;
            if (!ipv6)
            {
                state = ReadInt(row, 0);
                local = Ip4(row, 4); lport = Port(row, 8);
                remote = Ip4(row, 12); rport = Port(row, 16);
                pid = ReadInt(row, 20);
            }
            else
            {
                local = Ip6(row, 0, 16); lport = Port(row, 20);
                remote = Ip6(row, 24, 40); rport = Port(row, 44);
                state = ReadInt(row, 48);
                pid = ReadInt(row, 52);
            }
            result.Add(new Connection(ipv6 ? "TCP6" : "TCP", local, lport, remote, rport,
                StateName(state), pid, Resolve(resolver, pid)));
        }
        return result;
    }

    /// <summary>Parse une table UDP (IPv4 ou IPv6).</summary>
    public static IReadOnlyList<Connection> ParseUdp(ReadOnlySpan<byte> table, bool ipv6, ProcessNameResolver? resolver = null)
    {
        int rowSize = ipv6 ? Udp6RowSize : Udp4RowSize;
        var result = new List<Connection>();
        foreach (var row in Rows(table, rowSize))
        {
            string local; int lport, pid;
            if (!ipv6) { local = Ip4(row, 0); lport = Port(row, 4); pid = ReadInt(row, 8); }
            else { local = Ip6(row, 0, 16); lport = Port(row, 20); pid = ReadInt(row, 24); }
            // UDP n'a ni état ni pair distant.
            result.Add(new Connection(ipv6 ? "UDP6" : "UDP", local, lport, null, null, "-", pid, Resolve(resolver, pid)));
        }
        return result;
    }

    /// <summary>Nom lisible d'un état MIB_TCP_STATE.</summary>
    public static string StateName(int state) => state switch
    {
        1 => "CLOSED", 2 => "LISTEN", 3 => "SYN_SENT", 4 => "SYN_RCVD", 5 => "ESTABLISHED",
        6 => "FIN_WAIT1", 7 => "FIN_WAIT2", 8 => "CLOSE_WAIT", 9 => "CLOSING", 10 => "LAST_ACK",
        11 => "TIME_WAIT", 12 => "DELETE_TCB", _ => $"UNKNOWN({state})"
    };

    private static string? Resolve(ProcessNameResolver? r, int pid)
    {
        if (r is null) return null;
        try { return r(pid); } catch { return null; }
    }

    // Découpe en lignes en ignorant toute ligne qui dépasserait le tampon (robustesse).
    private static List<byte[]> Rows(ReadOnlySpan<byte> table, int rowSize)
    {
        var list = new List<byte[]>();
        if (table.Length < 4) return list;
        long declared = (uint)BinaryPrimitives.ReadInt32LittleEndian(table);
        long available = (table.Length - 4) / rowSize;
        long count = Math.Min(declared, available);
        for (int i = 0; i < count; i++)
            list.Add(table.Slice(4 + i * rowSize, rowSize).ToArray());
        return list;
    }

    private static int ReadInt(byte[] b, int off) => BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(off, 4));

    // Le port est en ordre réseau dans les 2 octets de poids faible du DWORD.
    private static int Port(byte[] b, int off) => (b[off] << 8) | b[off + 1];

    private static string Ip4(byte[] b, int off) => new IPAddress(b.AsSpan(off, 4)).ToString();

    private static string Ip6(byte[] b, int addrOff, int scopeOff)
        => new IPAddress(b.AsSpan(addrOff, 16), (uint)ReadInt(b, scopeOff)).ToString();
}
