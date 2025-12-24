using Microsoft.Win32;
using ForensicCollector.Models;
using System.Runtime.Versioning;
using ForensicCollector.Util;

namespace ForensicCollector.Collectors;

[SupportedOSPlatform("windows")]
public static class IfeoCollector
{
    public static List<IfeoEntry> Collect()
    {
        var list = new List<IfeoEntry>();
        try
        {
            var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var ifeo = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options");
            if (ifeo != null)
            {
                foreach (var exe in ifeo.GetSubKeyNames())
                {
                    using var k = ifeo.OpenSubKey(exe);
                    if (k == null) continue;
                    string dbg = k.GetValue("Debugger")?.ToString() ?? string.Empty;
                    string gfl = k.GetValue("GlobalFlag")?.ToString() ?? string.Empty;
                    if (!string.IsNullOrEmpty(dbg) || !string.IsNullOrEmpty(gfl))
                    {
                        list.Add(new IfeoEntry { ExeName = exe, Debugger = dbg, GlobalFlag = gfl });
                    }
                }
            }
        }
        catch (Exception ex) { Logger.Warn("IFEO", ex); }
        return list;
    }
}
