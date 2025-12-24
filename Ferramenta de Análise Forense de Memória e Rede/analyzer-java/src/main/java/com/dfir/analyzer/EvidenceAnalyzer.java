package com.dfir.analyzer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class EvidenceAnalyzer {
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
                System.out.println("Uso: java -jar analyzer.jar <pacote.fpkg> <senha> <relatorio.pdf> [--ioc-json <path>] [--ioc-csv <path>] [--no-network]");
            return;
        }
        File pkg = new File(args[0]);
        String password = args[1];
        File outPdf = new File(args[2]);

        if (hasFlag(args, "--no-network")) {
            NetOptions.setAllowNetwork(false);
            System.out.println("Modo offline ativado: consultas de rede desabilitadas (DNS/WHOIS)");
        }

        System.out.println("Lendo e descriptografando pacote...");
        PackageReader.Result res = PackageReader.readAndDecrypt(pkg, password);
        String json = new String(res.data, StandardCharsets.UTF_8);
        Gson gson = new GsonBuilder().create();
        EvidencePackage ev = gson.fromJson(json, EvidencePackage.class);

        System.out.println("Rodando heurísticas DFIR...");
        List<Heuristics.Finding> findings = Heuristics.analyze(ev);

        System.out.println("Gerando relatório PDF...");
        PdfReportGenerator.generate(outPdf, ev, findings, res.signaturePresent, res.signatureValid);
            String iocJson = getArg(args, "--ioc-json");
            String iocCsv = getArg(args, "--ioc-csv");
        
            if (iocJson != null) {
                exportFindingsJson(findings, new File(iocJson));
                System.out.println("IOCs JSON: " + iocJson);
            }
            if (iocCsv != null) {
                exportFindingsCsv(findings, new File(iocCsv));
                System.out.println("IOCs CSV: " + iocCsv);
            }
        System.out.println("Relatório gerado em: " + outPdf.getAbsolutePath());
    }

        private static void exportFindingsJson(java.util.List<Heuristics.Finding> findings, File f) throws Exception {
            com.google.gson.Gson g = new com.google.gson.GsonBuilder().setPrettyPrinting().create();
            try (java.io.FileWriter w = new java.io.FileWriter(f)) { w.write(g.toJson(findings)); }
        }

        private static void exportFindingsCsv(java.util.List<Heuristics.Finding> findings, File f) throws Exception {
            try (java.io.PrintWriter pw = new java.io.PrintWriter(f)) {
                pw.println("severity,summary,detail,attackId,attackTactic");
                for (Heuristics.Finding x : findings) {
                    pw.printf("%s,%s,%s,%s,%s%n", esc(x.severity), esc(x.summary), esc(x.detail), esc(x.attackId), esc(x.attackTactic));
                }
            }
        }

        private static String esc(String s) { if (s == null) return ""; return s.replace("\"", "'").replace(",", " "); }

        private static String getArg(String[] args, String key) {
            for (int i=0;i<args.length-1;i++) { if (args[i].equals(key)) return args[i+1]; }
            return null;
        }

        private static boolean hasFlag(String[] args, String key) {
            for (String a : args) { if (a.equals(key)) return true; }
            return false;
        }
}
