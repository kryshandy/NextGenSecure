using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CoreGuard.Network;

/// <summary>
/// Énumère les connexions TCP/UDP (IPv4 + IPv6) via l'API IP Helper
/// (GetExtendedTcpTable / GetExtendedUdpTable) et associe chaque PID à un nom de processus.
/// </summary>
public static class PortInspector
{
    private const int AfInet = 2, AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int NoError = 0;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

    /// <summary>Retourne toutes les connexions ; une famille en échec est ignorée (jamais d'exception).</summary>
    public static IReadOnlyList<Connection> GetConnections()
    {
        var names = new Dictionary<int, string?>();
        string? Resolver(int pid)
        {
            if (names.TryGetValue(pid, out var n)) return n;
            n = ResolveProcessName(pid);
            names[pid] = n;
            return n;
        }

        var all = new List<Connection>();
        Collect(all, () => TcpTableParser.ParseTcp(Fetch(true, AfInet), false, Resolver));
        Collect(all, () => TcpTableParser.ParseTcp(Fetch(true, AfInet6), true, Resolver));
        Collect(all, () => TcpTableParser.ParseUdp(Fetch(false, AfInet), false, Resolver));
        Collect(all, () => TcpTableParser.ParseUdp(Fetch(false, AfInet6), true, Resolver));
        return all;
    }

    private static void Collect(List<Connection> into, Func<IReadOnlyList<Connection>> source)
    {
        try { into.AddRange(source()); }
        catch (Exception) { /* famille indisponible (ex. IPv6 désactivé) : on continue */ }
    }

    // La table peut grandir entre deux appels : on réessaie avec un tampon plus large.
    private static byte[] Fetch(bool tcp, int family)
    {
        int size = 0;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            IntPtr buf = IntPtr.Zero;
            try
            {
                buf = Marshal.AllocHGlobal(Math.Max(size, 1));
                int rc = tcp
                    ? GetExtendedTcpTable(buf, ref size, true, family, TcpTableOwnerPidAll, 0)
                    : GetExtendedUdpTable(buf, ref size, true, family, UdpTableOwnerPid, 0);
                if (rc == NoError)
                {
                    var bytes = new byte[size];
                    Marshal.Copy(buf, bytes, 0, size);
                    return bytes;
                }
                if (rc != ErrorInsufficientBuffer)
                    throw new System.ComponentModel.Win32Exception(rc);
                size += 4096; // marge de croissance
            }
            finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        }
        throw new InvalidOperationException("Table réseau instable : tampon insuffisant après plusieurs essais.");
    }

    private static string? ResolveProcessName(int pid)
    {
        if (pid == 0) return "System Idle";
        if (pid == 4) return "System";
        try { using var p = Process.GetProcessById(pid); return p.ProcessName; }
        catch { return null; } // processus terminé ou accès refusé
    }
}
