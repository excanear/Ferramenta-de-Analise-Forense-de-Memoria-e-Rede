using Microsoft.Win32;
using ForensicCollector.Models;
using System.Runtime.Versioning;
using ForensicCollector.Util;

namespace ForensicCollector.Collectors;

[SupportedOSPlatform("windows")]
public static class AppInitCollector
{
    public static AppInitInfo Collect()
    {
        var info = new AppInitInfo();
        try
        {
            var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var winKey = baseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
            if (winKey != null)
            {
                info.AppInitDlls = winKey.GetValue("AppInit_DLLs")?.ToString() ?? string.Empty;
                info.LoadAppInitDlls = (winKey.GetValue("LoadAppInit_DLLs") is int la) && la != 0;
                info.RequireSignedAppInitDlls = (winKey.GetValue("RequireSignedAppInit_DLLs") is int rs) && rs != 0;
            }
        }
        catch (Exception ex) { Logger.Warn("AppInit_DLLs", ex); }
        return info;
    }
}
