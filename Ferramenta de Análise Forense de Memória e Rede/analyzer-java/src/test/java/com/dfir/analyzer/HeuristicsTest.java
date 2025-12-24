package com.dfir.analyzer;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

public class HeuristicsTest {
    @Test
    public void testStartupAndAppInitFindings() {
        EvidencePackage ev = new EvidencePackage();
        ev.Processes = new ArrayList<>();
        ev.Connections = new ArrayList<>();
        ev.Registry = new RegistryInfo();
        ev.Registry.RunKeys = new ArrayList<>();
        ev.Registry.Services = new ArrayList<>();
        ev.ScheduledTasks = new ArrayList<>();
        ev.WmiSubscriptions = new ArrayList<>();
        ev.StartupItems = new ArrayList<>();
        ev.IfeoEntries = new ArrayList<>();
        ev.AppInit = new AppInitInfo();

        StartupItem si = new StartupItem();
        si.Scope = "CurrentUser";
        si.Path = "C\\Users\\Henry\\AppData\\Roaming\\bad.lnk";
        si.IsLink = true;
        ev.StartupItems.add(si);

        ev.AppInit.LoadAppInitDlls = true;
        ev.AppInit.AppInitDlls = "C\\Users\\Henry\\AppData\\Roaming\\evil.dll";

        List<Heuristics.Finding> findings = Heuristics.analyze(ev);
        assertTrue(findings.stream().anyMatch(f -> f.summary.contains("Item de inicialização")));
        assertTrue(findings.stream().anyMatch(f -> f.summary.contains("AppInit_DLLs")));
    }
}
