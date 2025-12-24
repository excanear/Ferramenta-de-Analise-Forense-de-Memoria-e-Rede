using System.Diagnostics;
using System.Management;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ForensicCollector.Models;
using System.Runtime.Versioning;
using ForensicCollector.Util;

namespace ForensicCollector.Collectors;

[SupportedOSPlatform("windows")]
public static class ProcessCollector
{
    public static List<ProcessInfo> CollectProcesses()
    {
        var processes = Process.GetProcesses();
        var withWindows = GetPidsWithWindows();
        var ntPids = NtQuerySystemProcessPids();
        var ntPidSet = new HashSet<int>(ntPids);

        // WMI enrichment: ParentPID + CommandLine
        var ppidMap = new Dictionary<int, int>();
        var cmdMap = new Dictionary<int, string?>();
        try
        {
            var searcher = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, CommandLine FROM Win32_Process");
            foreach (ManagementObject mo in searcher.Get())
            {
                int pid = Convert.ToInt32(mo["ProcessId"] ?? 0);
                int ppid = Convert.ToInt32(mo["ParentProcessId"] ?? 0);
                string? cmd = mo["CommandLine"] as string;
                ppidMap[pid] = ppid;
                cmdMap[pid] = cmd;
            }
        }
        catch (Exception ex) { Logger.Warn("WMI Win32_Process", ex); }

        var list = new List<ProcessInfo>();
        foreach (var p in processes)
        {
            string name = string.Empty;
            string? path = null;
            try { name = p.ProcessName; } catch (Exception ex) { Logger.Warn($"ProcessName PID={p.Id}", ex); }
            try { path = p.MainModule?.FileName; } catch (Exception ex) { Logger.Warn($"MainModule PID={p.Id}", ex); }
            var info = new ProcessInfo
            {
                Pid = p.Id,
                Name = name,
                Path = path,
                HasWindow = withWindows.Contains(p.Id),
                IsHiddenCandidate = !ntPidSet.Contains(p.Id),
                ParentPid = ppidMap.TryGetValue(p.Id, out var pp) ? pp : 0,
                CommandLine = cmdMap.TryGetValue(p.Id, out var cmdl) ? cmdl : null
            };

            // Hash & signature
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                try
                {
                    using var fs = File.OpenRead(path);
                    using var sha = SHA256.Create();
                    var hash = sha.ComputeHash(fs);
                    info.Sha256 = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
                catch (Exception ex) { Logger.Warn($"SHA256 {path}", ex); }
                try
                {
                    var cert = X509Certificate.CreateFromSignedFile(path);
                    var cert2 = new X509Certificate2(cert);
                    info.IsSigned = true;
                    info.Publisher = cert2.Subject;
                }
                catch (Exception ex) { info.IsSigned = false; Logger.Warn($"Authenticode {path}", ex); }
            }
            list.Add(info);
        }

        // Add processes present in NtQuery but not visible via Process API -> hidden candidates
        var knownPids = processes.Select(x => x.Id).ToHashSet();
        foreach (var pid in ntPids)
        {
            if (!knownPids.Contains(pid))
            {
                list.Add(new ProcessInfo
                {
                    Pid = pid,
                    Name = "(desconhecido)",
                    Path = null,
                    HasWindow = false,
                    IsHiddenCandidate = true
                });
            }
        }
        return list.OrderBy(p => p.Pid).ToList();
    }

    private static HashSet<int> GetPidsWithWindows()
    {
        var set = new HashSet<int>();
        EnumWindows((hWnd, lParam) =>
        {
            if (!IsWindowVisible(hWnd)) return true;
            GetWindowThreadProcessId(hWnd, out uint pid);
            if (pid != 0) set.Add((int)pid);
            return true;
        }, IntPtr.Zero);
        return set;
    }

    private static List<int> NtQuerySystemProcessPids()
    {
        const int SystemProcessInformation = 5;
        int status;
        int bufferSize = 0x10000;
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            while (true)
            {
                status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, out int needed);
                if (status == 0) break; // STATUS_SUCCESS
                if (status == unchecked((int)0xC0000004)) // STATUS_INFO_LENGTH_MISMATCH
                {
                    bufferSize = Math.Max(bufferSize * 2, needed);
                    Marshal.FreeHGlobal(buffer);
                    buffer = Marshal.AllocHGlobal(bufferSize);
                    continue;
                }
                // other error
                return new List<int>();
            }

            var pids = new List<int>();
            IntPtr current = buffer;
            while (true)
            {
                var spi = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(current);
                pids.Add((int)spi.UniqueProcessId);
                if (spi.NextEntryOffset == 0) break;
                current = IntPtr.Add(current, (int)spi.NextEntryOffset);
            }
            return pids;
        }
        catch (Exception ex)
        {
            Logger.Warn("NtQuerySystemInformation", ex);
            return new List<int>();
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_PROCESS_INFORMATION
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;
        private long Reserved1;
        private long Reserved2;
        private long Reserved3;
        public long CreateTime;
        public long UserTime;
        public long KernelTime;
        public IntPtr ImageName; // UNICODE_STRING* (we ignore)
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
        public uint HandleCount;
        public uint SessionId;
        public IntPtr UniqueProcessKey;
        public IntPtr PeakVirtualSize;
        public IntPtr VirtualSize;
        public uint PageFaultCount;
        public IntPtr PeakWorkingSetSize;
        public IntPtr WorkingSetSize;
        public IntPtr QuotaPeakPagedPoolUsage;
        public IntPtr QuotaPagedPoolUsage;
        public IntPtr QuotaPeakNonPagedPoolUsage;
        public IntPtr QuotaNonPagedPoolUsage;
        public IntPtr PagefileUsage;
        public IntPtr PeakPagefileUsage;
        public IntPtr PrivatePageCount;
        public long ReadOperationCount;
        public long WriteOperationCount;
        public long OtherOperationCount;
        public long ReadTransferCount;
        public long WriteTransferCount;
        public long OtherTransferCount;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
