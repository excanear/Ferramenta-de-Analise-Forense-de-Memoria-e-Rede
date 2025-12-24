using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ForensicCollector.Models;
using ForensicCollector.Util;

namespace ForensicCollector.Collectors;

[SupportedOSPlatform("windows")]
public static class NetworkCollector
{
    public static List<ConnectionInfo> CollectConnections()
    {
        var list = new List<ConnectionInfo>();
        list.AddRange(GetTcpConnections());
        list.AddRange(GetUdpConnections());
        list.AddRange(GetTcpConnectionsV6());
        list.AddRange(GetUdpConnectionsV6());
        return list.OrderBy(c => c.Pid).ThenBy(c => c.LocalPort).ToList();
    }

    private static IEnumerable<ConnectionInfo> GetTcpConnections()
    {
        int buffSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
        IntPtr buff = Marshal.AllocHGlobal(buffSize);
        try
        {
            int res = GetExtendedTcpTable(buff, ref buffSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (res != 0) { Logger.Warn("GetExtendedTcpTable IPv4", new Exception($"res={res}")); yield break; }
            int numEntries = Marshal.ReadInt32(buff);
            IntPtr rowPtr = IntPtr.Add(buff, 4);
            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                var local = new IPEndPoint(row.localAddr, ntohs((ushort)row.localPort));
                var remote = new IPEndPoint(row.remoteAddr, ntohs((ushort)row.remotePort));
                yield return new ConnectionInfo
                {
                    Protocol = "TCP",
                    LocalAddress = local.Address.ToString(),
                    LocalPort = local.Port,
                    RemoteAddress = remote.Address.ToString(),
                    RemotePort = remote.Port,
                    State = ((TcpState)row.state).ToString(),
                    Pid = (int)row.owningPid,
                    ProcessName = TryGetProcessName((int)row.owningPid)
                };
                rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_TCPROW_OWNER_PID>());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buff);
        }
    }

    private static IEnumerable<ConnectionInfo> GetUdpConnections()
    {
        int buffSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
        IntPtr buff = Marshal.AllocHGlobal(buffSize);
        try
        {
            int res = GetExtendedUdpTable(buff, ref buffSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (res != 0) { Logger.Warn("GetExtendedUdpTable IPv4", new Exception($"res={res}")); yield break; }
            int numEntries = Marshal.ReadInt32(buff);
            IntPtr rowPtr = IntPtr.Add(buff, 4);
            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                var local = new IPEndPoint(row.localAddr, ntohs((ushort)row.localPort));
                yield return new ConnectionInfo
                {
                    Protocol = "UDP",
                    LocalAddress = local.Address.ToString(),
                    LocalPort = local.Port,
                    RemoteAddress = "",
                    RemotePort = 0,
                    State = "",
                    Pid = (int)row.owningPid,
                    ProcessName = TryGetProcessName((int)row.owningPid)
                };
                rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_UDPROW_OWNER_PID>());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buff);
        }
    }

    private static string TryGetProcessName(int pid)
    {
        try { return System.Diagnostics.Process.GetProcessById(pid).ProcessName; } catch { return string.Empty; }
    }

    private const int AF_INET = 2;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TCP_TABLE_CLASS tblClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UDP_TABLE_CLASS tblClass, int reserved);

    private enum TCP_TABLE_CLASS { TCP_TABLE_OWNER_PID_ALL = 5 }
    private enum UDP_TABLE_CLASS { UDP_TABLE_OWNER_PID = 1 }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    private static int ntohs(ushort netshort) => (ushort)IPAddress.NetworkToHostOrder((short)netshort);

    private enum TcpState : uint
    {
        Closed = 1,
        Listen,
        SynSent,
        SynReceived,
        Established,
        FinWait1,
        FinWait2,
        CloseWait,
        Closing,
        LastAck,
        TimeWait,
        DeleteTcb
    }

    // IPv6 support
    private const int AF_INET6 = 23;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        public uint owningPid;
    }

    private static IEnumerable<ConnectionInfo> GetTcpConnectionsV6()
    {
        int buffSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, AF_INET6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
        IntPtr buff = Marshal.AllocHGlobal(buffSize);
        try
        {
            int res = GetExtendedTcpTable(buff, ref buffSize, true, AF_INET6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (res != 0) { Logger.Warn("GetExtendedTcpTable IPv6", new Exception($"res={res}")); yield break; }
            int numEntries = Marshal.ReadInt32(buff);
            IntPtr rowPtr = IntPtr.Add(buff, 4);
            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                var local = new IPEndPoint(new IPAddress(row.localAddr, (long)row.localScopeId), ntohs((ushort)row.localPort));
                var remote = new IPEndPoint(new IPAddress(row.remoteAddr, (long)row.remoteScopeId), ntohs((ushort)row.remotePort));
                yield return new ConnectionInfo
                {
                    Protocol = "TCP",
                    LocalAddress = local.Address.ToString(),
                    LocalPort = local.Port,
                    RemoteAddress = remote.Address.ToString(),
                    RemotePort = remote.Port,
                    State = ((TcpState)row.state).ToString(),
                    Pid = (int)row.owningPid,
                    ProcessName = TryGetProcessName((int)row.owningPid),
                    AddressFamily = "IPv6"
                };
                rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buff);
        }
    }

    private static IEnumerable<ConnectionInfo> GetUdpConnectionsV6()
    {
        int buffSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, AF_INET6, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
        IntPtr buff = Marshal.AllocHGlobal(buffSize);
        try
        {
            int res = GetExtendedUdpTable(buff, ref buffSize, true, AF_INET6, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (res != 0) { Logger.Warn("GetExtendedUdpTable IPv6", new Exception($"res={res}")); yield break; }
            int numEntries = Marshal.ReadInt32(buff);
            IntPtr rowPtr = IntPtr.Add(buff, 4);
            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                var local = new IPEndPoint(new IPAddress(row.localAddr, (long)row.localScopeId), ntohs((ushort)row.localPort));
                yield return new ConnectionInfo
                {
                    Protocol = "UDP",
                    LocalAddress = local.Address.ToString(),
                    LocalPort = local.Port,
                    RemoteAddress = "",
                    RemotePort = 0,
                    State = "",
                    Pid = (int)row.owningPid,
                    ProcessName = TryGetProcessName((int)row.owningPid),
                    AddressFamily = "IPv6"
                };
                rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buff);
        }
    }
}
