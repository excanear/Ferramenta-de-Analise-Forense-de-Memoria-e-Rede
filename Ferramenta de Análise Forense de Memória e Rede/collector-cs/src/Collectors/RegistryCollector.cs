using Microsoft.Win32;
using System.Runtime.Versioning;
using ForensicCollector.Models;
using ForensicCollector.Util;

namespace ForensicCollector.Collectors;

[SupportedOSPlatform("windows")]
public static class RegistryCollector
{
    public static RegistryInfo CollectPersistence()
    {
        var info = new RegistryInfo();
        // Run keys HKLM/HKCU
        try
        {
            CollectRunKey(info.RunKeys, RegistryHive.LocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            CollectRunKey(info.RunKeys, RegistryHive.LocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
            CollectRunKey(info.RunKeys, RegistryHive.CurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            CollectRunKey(info.RunKeys, RegistryHive.CurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        }
        catch (Exception ex)
        {
            Logger.Warn("Registry Run keys", ex);
        }

        // Services (HKLM\SYSTEM\CurrentControlSet\Services)
        try
        {
            var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var servicesKey = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services");
            if (servicesKey != null)
            {
                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName);
                        if (svcKey == null) continue;
                        var imagePath = svcKey.GetValue("ImagePath")?.ToString() ?? string.Empty;
                        var startObj = svcKey.GetValue("Start");
                        int startType = startObj is int i ? i : 0;
                        info.Services.Add(new ServiceEntry { Name = svcName, ImagePath = imagePath, StartType = startType });
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn($"Registry Service: {svcName}", ex);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Warn("Registry Services", ex);
        }
        return info;
    }

    private static void CollectRunKey(List<RunKeyEntry> entries, RegistryHive hive, string path)
    {
        var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        using var runKey = baseKey.OpenSubKey(path);
        if (runKey == null) return;
        foreach (var name in runKey.GetValueNames())
        {
            var value = runKey.GetValue(name)?.ToString() ?? string.Empty;
            entries.Add(new RunKeyEntry
            {
                Hive = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU",
                KeyPath = path,
                Name = name,
                Value = value
            });
        }
    }
}
