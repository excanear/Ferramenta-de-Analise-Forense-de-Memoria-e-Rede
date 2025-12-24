using System.Xml;
using System.IO;
using System.Runtime.Versioning;
using ForensicCollector.Models;
using ForensicCollector.Util;

namespace ForensicCollector.Collectors;

[SupportedOSPlatform("windows")]
public static class ScheduledTaskCollector
{
    public static List<ScheduledTaskEntry> Collect()
    {
        var tasks = new List<ScheduledTaskEntry>();
        try
        {
            string baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (!Directory.Exists(baseDir)) return tasks;
            foreach (var file in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
            {
                try
                {
                    var xml = new XmlDocument();
                    xml.Load(file);
                    var entry = new ScheduledTaskEntry
                    {
                        TaskPath = "\\" + Path.GetRelativePath(baseDir, file).Replace(Path.DirectorySeparatorChar, '\\'),
                        Name = Path.GetFileName(file),
                        Enabled = GetBool(xml, "/Task/Settings/Enabled") ?? true,
                        ExecPath = GetText(xml, "/Task/Actions/Exec/Command") ?? string.Empty,
                        Arguments = GetText(xml, "/Task/Actions/Exec/Arguments") ?? string.Empty
                    };
                    tasks.Add(entry);
                }
                catch (Exception ex)
                {
                    Logger.Warn($"Scheduled Task parse: {file}", ex);
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Warn("Scheduled Tasks enumeration", ex);
        }
        return tasks;
    }

    private static string? GetText(XmlDocument doc, string xpath)
    {
        var node = doc.SelectSingleNode(xpath);
        return node?.InnerText;
    }

    private static bool? GetBool(XmlDocument doc, string xpath)
    {
        var t = GetText(doc, xpath);
        if (t == null) return null;
        if (bool.TryParse(t, out var b)) return b;
        return null;
    }
}
