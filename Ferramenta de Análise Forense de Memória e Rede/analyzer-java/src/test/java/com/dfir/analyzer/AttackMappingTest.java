package com.dfir.analyzer;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

public class AttackMappingTest {
    @Test
    public void testAttackIdsPresent() {
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

        // Simulate suspicious run key
        RunKeyEntry r = new RunKeyEntry();
        r.Hive = "HKCU"; r.KeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"; r.Value = "C\\Users\\u\\AppData\\evil.exe";
        ev.Registry.RunKeys.add(r);

        List<Heuristics.Finding> findings = Heuristics.analyze(ev);
        assertTrue(findings.stream().anyMatch(f -> "T1060".equals(f.attackId)));
    }
}
