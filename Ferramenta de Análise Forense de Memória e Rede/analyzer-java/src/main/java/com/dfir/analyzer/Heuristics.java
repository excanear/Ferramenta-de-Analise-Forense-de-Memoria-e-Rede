package com.dfir.analyzer;

import java.net.InetAddress;
import java.util.*;

public class Heuristics {
    public static class Finding {
        public String severity; // High/Medium/Low
        public String summary;
        public String detail;
        public String attackId; // MITRE ATT&CK technique id
        public String attackTactic;
    }

    public static List<Finding> analyze(EvidencePackage ev) {
        List<Finding> out = new ArrayList<>();
        Set<Integer> pidsNoWindow = new HashSet<>();
        for (ProcessInfo p : ev.Processes) if (!p.HasWindow) pidsNoWindow.add(p.Pid);

        Map<String, Integer> connCounts = new HashMap<>();
        for (ConnectionInfo c : ev.Connections) {
            if (c.Protocol.equals("TCP") && isExternalIp(c.RemoteAddress)) {
                boolean commonPort = (c.RemotePort == 80 || c.RemotePort == 443);
                boolean noWindow = pidsNoWindow.contains(c.Pid);
                if (noWindow && !commonPort) {
                    out.add(f("High", "Processo sem janela conectado externamente", String.format("PID %d (%s) => %s:%d", c.Pid, nullToEmpty(c.ProcessName), c.RemoteAddress, c.RemotePort), "T1041", "Exfiltration"));
                } else if (!commonPort) {
                    out.add(f("Medium", "Conexão externa incomum", String.format("PID %d (%s) => %s:%d", c.Pid, nullToEmpty(c.ProcessName), c.RemoteAddress, c.RemotePort), "T1071", "Command and Control"));
                }
            }
            // Beaconing heuristic (snapshot): multiple connections to same remote by same PID
            String key = c.Pid + "|" + c.RemoteAddress + "|" + c.RemotePort;
            connCounts.put(key, connCounts.getOrDefault(key, 0) + 1);
        }

        for (Map.Entry<String, Integer> e : connCounts.entrySet()) {
            if (e.getValue() >= 5) {
                String[] parts = e.getKey().split("\\|");
                int pid = Integer.parseInt(parts[0]);
                String ip = parts[1];
                int port = Integer.parseInt(parts[2]);
                out.add(f("Medium", "Múltiplas conexões para o mesmo destino (possível beaconing)", String.format("PID %d => %s:%d (%d conexões)", pid, ip, port, e.getValue()), "T1071", "Command and Control"));
            }
        }

        // Tarefas agendadas suspeitas
        if (ev.ScheduledTasks != null) {
            for (ScheduledTaskEntry t : ev.ScheduledTasks) {
                String path = (t.ExecPath == null ? "" : t.ExecPath).toLowerCase(Locale.ROOT);
                if (path.contains("appdata") || path.contains("temp") || path.contains("\\users\\")) {
                    out.add(f("Medium", "Tarefa agendada executando em pasta de usuário", String.format("%s => %s %s", t.TaskPath, t.ExecPath, nullToEmpty(t.Arguments)), "T1053", "Execution"));
                }
                if (path.endsWith(".bat") || path.endsWith(".js") || path.endsWith(".vbs")) {
                    out.add(f("Low", "Tarefa agendada executando script", String.format("%s => %s %s", t.TaskPath, t.ExecPath, nullToEmpty(t.Arguments)), "T1059", "Execution"));
                }
            }
        }

        // WMI persistência
                // Startup folders
                if (ev.StartupItems != null) {
                    for (StartupItem si : ev.StartupItems) {
                        String p = si.Path == null ? "" : si.Path.toLowerCase(Locale.ROOT);
                        if (p.contains("appdata") || p.contains("temp") || p.contains("\\users\\")) {
                            out.add(f("Medium", "Item de inicialização em pasta de usuário", String.format("%s => %s", si.Scope, si.Path), "T1060", "Persistence"));
                        }
                        if (si.IsLink && (p.endsWith(".lnk"))) {
                            out.add(f("Low", "Atalho em inicialização", String.format("%s => %s", si.Scope, si.Path), "T1204", "Execution"));
                        }
                    }
                }

                // IFEO
                if (ev.IfeoEntries != null) {
                    for (IfeoEntry e : ev.IfeoEntries) {
                        if (e.Debugger != null && !e.Debugger.isBlank()) {
                            out.add(f("High", "IFEO Debugger configurado", String.format("%s => %s", e.ExeName, e.Debugger), "T1112", "Defense Evasion"));
                        }
                    }
                }

                // AppInit_DLLs
                if (ev.AppInit != null) {
                    if (ev.AppInit.LoadAppInitDlls && ev.AppInit.AppInitDlls != null && !ev.AppInit.AppInitDlls.isBlank()) {
                        String dlls = ev.AppInit.AppInitDlls.toLowerCase(Locale.ROOT);
                        if (dlls.contains("appdata") || dlls.contains("temp") || dlls.contains("\\users\\")) {
                            out.add(f("High", "AppInit_DLLs carregando DLLs em pasta suspeita", "DLLs=" + ev.AppInit.AppInitDlls, "T1103", "Persistence"));
                        } else {
                            out.add(f("Medium", "AppInit_DLLs configurado", "DLLs=" + ev.AppInit.AppInitDlls, "T1103", "Persistence"));
                        }
                    }
                }
        if (ev.WmiSubscriptions != null) {
            for (WmiSubscription w : ev.WmiSubscriptions) {
                String cmd = (w.CommandLine == null ? "" : w.CommandLine).toLowerCase(Locale.ROOT);
                String script = (w.ScriptText == null ? "" : w.ScriptText).toLowerCase(Locale.ROOT);
                if ((cmd.contains("appdata") || cmd.contains("temp") || cmd.contains("\\users\\")) ||
                    (script.contains("powershell") || script.contains("cscript") || script.contains("wscript"))) {
                    out.add(f("High", "Assinatura WMI suspeita", String.format("Filter=%s Consumer=%s Type=%s", w.FilterName, w.ConsumerName, w.ConsumerType), "T1047", "Execution"));
                }
            }
        }

        for (RunKeyEntry r : ev.Registry.RunKeys) {
            String v = r.Value.toLowerCase(Locale.ROOT);
            if (v.contains("appdata") || v.contains("temp") || v.contains("\\users\\")) {
                out.add(f("Medium", "Persistência em pasta de usuário", String.format("%s \\ %s = %s", r.Hive, r.KeyPath, r.Value), "T1060", "Persistence"));
            }
            if (v.endsWith(".bat") || v.endsWith(".js") || v.endsWith(".vbs")) {
                out.add(f("Low", "Script em chave de execução", String.format("%s \\ %s = %s", r.Hive, r.KeyPath, r.Value), "T1059", "Execution"));
            }
        }

        for (ServiceEntry s : ev.Registry.Services) {
            String p = s.ImagePath == null ? "" : s.ImagePath.toLowerCase(Locale.ROOT);
            if (s.StartType == 2) {
                if (p.contains("temp") || p.contains("appdata") || p.contains("\\users\\")) {
                    out.add(f("High", "Serviço auto-inicializável em pasta suspeita", String.format("%s (%s)", s.Name, s.ImagePath), "T1543", "Persistence"));
                }
            }
        }

        for (ProcessInfo p : ev.Processes) {
            if (p.IsHiddenCandidate) {
                out.add(f("High", "Processo potencialmente oculto", String.format("PID %d (%s) caminho=%s", p.Pid, p.Name, nullToEmpty(p.Path)), "T1057", "Discovery"));
            }
            if (p.CommandLine != null && p.CommandLine.toLowerCase(Locale.ROOT).contains("powershell")) {
                out.add(f("Medium", "Processo executando powershell", String.format("PID %d (%s) cmd=%s", p.Pid, p.Name, p.CommandLine), "T1059", "Execution"));
            }
            if (p.IsSigned == false) {
                out.add(f("Low", "Binário não assinado", String.format("PID %d (%s) hash=%s", p.Pid, p.Name, nullToEmpty(p.Sha256)), "T1036", "Defense Evasion"));
            }
        }
        return out;
    }

    private static boolean isExternalIp(String ip) {
        if (ip == null || ip.isBlank()) return false;
        try {
            InetAddress addr = InetAddress.getByName(ip);
            byte[] b = addr.getAddress();
            int first = b[0] & 0xFF;
            int second = b[1] & 0xFF;
            // RFC1918 + loopback
            if (first == 10) return false;
            if (first == 172 && (second >= 16 && second <= 31)) return false;
            if (first == 192 && second == 168) return false;
            if (first == 127) return false;
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static String resolveHost(String ip) {
        if (!NetOptions.isAllowNetwork()) return "";
        try { return InetAddress.getByName(ip).getHostName(); }
        catch (Exception e) { return ""; }
    }

    private static Finding f(String sev, String sum, String det, String attackId, String tactic) {
        Finding g = new Finding();
        g.severity = sev;
        g.summary = sum;
        g.detail = det;
        g.attackId = attackId;
        g.attackTactic = tactic;
        return g;
    }

    private static String nullToEmpty(String s) { return s == null ? "" : s; }
}
