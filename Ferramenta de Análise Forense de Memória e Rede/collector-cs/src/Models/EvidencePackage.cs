namespace ForensicCollector.Models;

public class EvidencePackage
{
    public DateTime TimestampUtc { get; set; }
    public SystemInfo SystemInfo { get; set; } = new();
    public List<ProcessInfo> Processes { get; set; } = new();
    public List<ConnectionInfo> Connections { get; set; } = new();
    public RegistryInfo Registry { get; set; } = new();
    public List<ScheduledTaskEntry> ScheduledTasks { get; set; } = new();
    public List<WmiSubscription> WmiSubscriptions { get; set; } = new();
    public List<StartupItem> StartupItems { get; set; } = new();
    public List<IfeoEntry> IfeoEntries { get; set; } = new();
    public AppInitInfo AppInit { get; set; } = new();
}

public class SystemInfo
{
    public string Hostname { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
}

public class ProcessInfo
{
    public int Pid { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Path { get; set; }
    public bool HasWindow { get; set; }
    public bool IsHiddenCandidate { get; set; }
    public int ParentPid { get; set; }
    public string? CommandLine { get; set; }
    public string? Sha256 { get; set; }
    public bool IsSigned { get; set; }
    public string? Publisher { get; set; }
}

public class ConnectionInfo
{
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty; // TCP/UDP
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty; // TCP state
    public string AddressFamily { get; set; } = "IPv4"; // IPv4/IPv6
}

public class RegistryInfo
{
    public List<RunKeyEntry> RunKeys { get; set; } = new();
    public List<ServiceEntry> Services { get; set; } = new();
}

public class RunKeyEntry
{
    public string Hive { get; set; } = string.Empty; // HKLM/HKCU
    public string KeyPath { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}

public class ServiceEntry
{
    public string Name { get; set; } = string.Empty;
    public string ImagePath { get; set; } = string.Empty;
    public int StartType { get; set; } // 2 = Auto, 3 = Manual, 4 = Disabled
}

public class ScheduledTaskEntry
{
    public string TaskPath { get; set; } = string.Empty; // e.g. \Microsoft\Windows\...
    public string Name { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public string ExecPath { get; set; } = string.Empty;
    public string Arguments { get; set; } = string.Empty;
}

public class WmiSubscription
{
    public string FilterName { get; set; } = string.Empty;
    public string FilterQuery { get; set; } = string.Empty;
    public string ConsumerName { get; set; } = string.Empty;
    public string ConsumerType { get; set; } = string.Empty; // CommandLineEventConsumer/ActiveScriptEventConsumer/etc.
    public string CommandLine { get; set; } = string.Empty;
    public string ScriptText { get; set; } = string.Empty;
}

public class StartupItem
{
    public string Scope { get; set; } = string.Empty; // CurrentUser/AllUsers
    public string Path { get; set; } = string.Empty;
    public bool IsLink { get; set; }
}

public class IfeoEntry
{
    public string ExeName { get; set; } = string.Empty;
    public string Debugger { get; set; } = string.Empty;
    public string GlobalFlag { get; set; } = string.Empty;
}

public class AppInitInfo
{
    public string AppInitDlls { get; set; } = string.Empty;
    public bool LoadAppInitDlls { get; set; }
    public bool RequireSignedAppInitDlls { get; set; }
}
