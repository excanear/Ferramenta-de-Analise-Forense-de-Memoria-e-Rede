using ForensicCollector.Models;
using System.Runtime.Versioning;
using System.IO;
using ForensicCollector.Util;

namespace ForensicCollector.Collectors;

[SupportedOSPlatform("windows")]
public static class StartupCollector
{
    public static List<StartupItem> Collect()
    {
        var list = new List<StartupItem>();
        try { list.AddRange(EnumDir("CurrentUser", Environment.GetFolderPath(Environment.SpecialFolder.Startup))); } catch (Exception ex) { Logger.Warn("Startup CurrentUser", ex); }
        try { list.AddRange(EnumDir("AllUsers", Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup))); } catch (Exception ex) { Logger.Warn("Startup AllUsers", ex); }
        return list;
    }

    private static IEnumerable<StartupItem> EnumDir(string scope, string? dir)
    {
        var items = new List<StartupItem>();
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return items;
        foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
        {
            items.Add(new StartupItem
            {
                Scope = scope,
                Path = f,
                IsLink = string.Equals(Path.GetExtension(f), ".lnk", StringComparison.OrdinalIgnoreCase)
            });
        }
        return items;
    }
}
