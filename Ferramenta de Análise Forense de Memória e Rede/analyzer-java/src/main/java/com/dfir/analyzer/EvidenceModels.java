package com.dfir.analyzer;

import java.util.*;

class EvidencePackage {
    Date TimestampUtc;
    SystemInfo SystemInfo;
    List<ProcessInfo> Processes;
    List<ConnectionInfo> Connections;
    RegistryInfo Registry;
    List<ScheduledTaskEntry> ScheduledTasks;
    List<WmiSubscription> WmiSubscriptions;
    List<StartupItem> StartupItems;
    List<IfeoEntry> IfeoEntries;
    AppInitInfo AppInit;
}

class SystemInfo { String Hostname; String Username; String OsVersion; }

class ProcessInfo { int Pid; String Name; String Path; boolean HasWindow; boolean IsHiddenCandidate; int ParentPid; String CommandLine; String Sha256; boolean IsSigned; String Publisher; }

class ConnectionInfo { int Pid; String ProcessName; String Protocol; String LocalAddress; int LocalPort; String RemoteAddress; int RemotePort; String State; String AddressFamily; }

class RegistryInfo { List<RunKeyEntry> RunKeys; List<ServiceEntry> Services; }

class RunKeyEntry { String Hive; String KeyPath; String Name; String Value; }

class ServiceEntry { String Name; String ImagePath; int StartType; }

class ScheduledTaskEntry { String TaskPath; String Name; boolean Enabled; String ExecPath; String Arguments; }

class WmiSubscription { String FilterName; String FilterQuery; String ConsumerName; String ConsumerType; String CommandLine; String ScriptText; }

class StartupItem { String Scope; String Path; boolean IsLink; }

class IfeoEntry { String ExeName; String Debugger; String GlobalFlag; }

class AppInitInfo { String AppInitDlls; boolean LoadAppInitDlls; boolean RequireSignedAppInitDlls; }
