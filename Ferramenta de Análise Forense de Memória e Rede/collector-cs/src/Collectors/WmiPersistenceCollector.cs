using System.Management;
using System.Runtime.Versioning;
using ForensicCollector.Models;
using ForensicCollector.Util;

namespace ForensicCollector.Collectors;

[SupportedOSPlatform("windows")]
public static class WmiPersistenceCollector
{
    public static List<WmiSubscription> Collect()
    {
        var list = new List<WmiSubscription>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();

            var filters = new Dictionary<string, (string Name, string Query)>();
            using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name, Query FROM __EventFilter")))
            {
                foreach (ManagementObject mo in searcher.Get())
                {
                    string name = (mo["Name"] as string) ?? string.Empty;
                    string query = (mo["Query"] as string) ?? string.Empty;
                    filters[name] = (name, query);
                }
            }

            var consumers = new Dictionary<string, (string Name, string Type, string? CommandLine, string? ScriptText)>();
            // CommandLineEventConsumer
            using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name, CommandLineTemplate FROM CommandLineEventConsumer")))
            {
                foreach (ManagementObject mo in searcher.Get())
                {
                    string name = (mo["Name"] as string) ?? string.Empty;
                    string cmd = (mo["CommandLineTemplate"] as string) ?? string.Empty;
                    consumers[name] = (name, "CommandLineEventConsumer", cmd, null);
                }
            }
            // ActiveScriptEventConsumer
            using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name, ScriptText FROM ActiveScriptEventConsumer")))
            {
                foreach (ManagementObject mo in searcher.Get())
                {
                    string name = (mo["Name"] as string) ?? string.Empty;
                    string script = (mo["ScriptText"] as string) ?? string.Empty;
                    consumers[name] = (name, "ActiveScriptEventConsumer", null, script);
                }
            }

            // Bindings
            using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Filter, Consumer FROM __FilterToConsumerBinding")))
            {
                foreach (ManagementObject mo in searcher.Get())
                {
                    string filterRef = (mo["Filter"] as string) ?? string.Empty;
                    string consumerRef = (mo["Consumer"] as string) ?? string.Empty;
                    // Extract names from references (format: __EventFilter.Name=\"foo\")
                    string filterName = ExtractName(filterRef);
                    string consumerName = ExtractName(consumerRef);

                    filters.TryGetValue(filterName, out var f);
                    consumers.TryGetValue(consumerName, out var c);

                    list.Add(new WmiSubscription
                    {
                        FilterName = f.Name,
                        FilterQuery = f.Query,
                        ConsumerName = c.Name,
                        ConsumerType = c.Type,
                        CommandLine = c.CommandLine ?? string.Empty,
                        ScriptText = c.ScriptText ?? string.Empty
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Warn("WMI persistence", ex);
        }
        return list;
    }

    private static string ExtractName(string reference)
    {
        // pattern: Class.Name=\"value\"
        int idx = reference.IndexOf("Name=\"");
        if (idx >= 0)
        {
            int start = idx + "Name=\"".Length;
            int end = reference.IndexOf("\"", start);
            if (end > start)
                return reference.Substring(start, end - start);
        }
        return reference;
    }
}
