package com.dfir.analyzer;

import com.lowagie.text.*;
import com.lowagie.text.pdf.*;
import java.awt.Color;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;

public class PdfReportGenerator {
    
    private static final Color PRIMARY_COLOR = new Color(41, 128, 185);
    private static final Color DANGER_COLOR = new Color(231, 76, 60);
    private static final Color WARNING_COLOR = new Color(243, 156, 18);
    private static final Color SUCCESS_COLOR = new Color(39, 174, 96);
    private static final Color DARK_GRAY = new Color(52, 73, 94);
    private static final Color LIGHT_GRAY = new Color(236, 240, 241);
    
    public static void generate(File outFile, EvidencePackage ev, java.util.List<Heuristics.Finding> findings,
                                boolean signaturePresent, Boolean signatureValid) throws Exception {
        Document doc = new Document(PageSize.A4, 50, 50, 50, 50);
        PdfWriter writer = PdfWriter.getInstance(doc, new FileOutputStream(outFile));
        
        HeaderFooter event = new HeaderFooter();
        writer.setPageEvent(event);
        
        doc.open();
        
        // Cover Page
        addCoverPage(doc, ev);
        doc.newPage();
        
        // Executive Summary
        addExecutiveSummary(doc, ev, findings, signaturePresent, signatureValid);
        doc.newPage();
        
        // Security Findings
        addSecurityFindings(doc, findings);
        doc.newPage();
        
        // Network Analysis
        addNetworkAnalysis(doc, ev);
        doc.newPage();
        
        // Persistence Mechanisms
        addPersistenceMechanisms(doc, ev);
        doc.newPage();
        
        // Process Analysis
        addProcessAnalysis(doc, ev);
        doc.newPage();
        
        // MITRE Mapping
        addMitreMapping(doc, findings);
        
        doc.close();
    }
    
    private static void addCoverPage(Document doc, EvidencePackage ev) throws DocumentException {
        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 24, PRIMARY_COLOR);
        Font h2Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, DARK_GRAY);
        Font smallFont = FontFactory.getFont(FontFactory.HELVETICA, 8, Color.GRAY);
        
        Paragraph title = new Paragraph("RELATORIO DE ANALISE FORENSE", titleFont);
        title.setAlignment(Element.ALIGN_CENTER);
        title.setSpacingAfter(20);
        doc.add(title);
        
        Paragraph subtitle = new Paragraph("Digital Forensics & Incident Response", h2Font);
        subtitle.setAlignment(Element.ALIGN_CENTER);
        subtitle.setSpacingAfter(50);
        doc.add(subtitle);
        
        PdfPTable infoTable = new PdfPTable(2);
        infoTable.setWidthPercentage(80);
        infoTable.setSpacingBefore(100);
        infoTable.setSpacingAfter(100);
        
        Font boldFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10);
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
        
        addInfoRow(infoTable, "Sistema Analisado:", ev.SystemInfo.Hostname, boldFont, normalFont);
        addInfoRow(infoTable, "Usuario:", ev.SystemInfo.Username, boldFont, normalFont);
        addInfoRow(infoTable, "Sistema Operacional:", ev.SystemInfo.OsVersion, boldFont, normalFont);
        addInfoRow(infoTable, "Data da Coleta:", new SimpleDateFormat("dd/MM/yyyy HH:mm:ss 'UTC'").format(new Date(ev.TimestampUtc.getTime())), boldFont, normalFont);
        addInfoRow(infoTable, "Data do Relatorio:", new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()), boldFont, normalFont);
        
        doc.add(infoTable);
        
        Paragraph footer = new Paragraph("\n\n\n\n\nRELATORIO CONFIDENCIAL", smallFont);
        footer.setAlignment(Element.ALIGN_CENTER);
        doc.add(footer);
    }
    
    private static void addExecutiveSummary(Document doc, EvidencePackage ev, java.util.List<Heuristics.Finding> findings,
                                           boolean signaturePresent, Boolean signatureValid) throws DocumentException {
        Font h1Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, DARK_GRAY);
        Font boldFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10);
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
        
        addSectionHeader(doc, "SUMARIO EXECUTIVO", h1Font);
        
        String riskLevel = calculateRiskLevel(findings);
        Color riskColor = getRiskColor(riskLevel);
        
        Paragraph risk = new Paragraph("Nivel de Risco: ", boldFont);
        Chunk riskChunk = new Chunk(riskLevel, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, riskColor));
        risk.add(riskChunk);
        risk.setSpacingAfter(10);
        doc.add(risk);
        
        PdfPTable statsTable = new PdfPTable(2);
        statsTable.setWidthPercentage(100);
        statsTable.setSpacingBefore(10);
        statsTable.setSpacingAfter(20);
        statsTable.setWidths(new int[]{3, 2});
        
        int high = 0, medium = 0, low = 0;
        for (Heuristics.Finding f : findings) {
            if ("High".equals(f.severity)) high++;
            else if ("Medium".equals(f.severity)) medium++;
            else low++;
        }
        
        addStatRow(statsTable, "Achados de Alta Severidade", String.valueOf(high), DANGER_COLOR);
        addStatRow(statsTable, "Achados de Media Severidade", String.valueOf(medium), WARNING_COLOR);
        addStatRow(statsTable, "Achados de Baixa Severidade", String.valueOf(low), SUCCESS_COLOR);
        addStatRow(statsTable, "Total de Processos", String.valueOf(ev.Processes.size()), PRIMARY_COLOR);
        addStatRow(statsTable, "Total de Conexoes", String.valueOf(ev.Connections.size()), PRIMARY_COLOR);
        
        doc.add(statsTable);
        
        // Signature Status
        Font h3Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, DARK_GRAY);
        addSubsectionHeader(doc, "Integridade do Pacote", h3Font);
        
        String sigText;
        Color sigColor;
        if (!signaturePresent) {
            sigText = "Pacote nao assinado";
            sigColor = WARNING_COLOR;
        } else if (signatureValid == null) {
            sigText = "Assinatura presente mas nao verificada";
            sigColor = WARNING_COLOR;
        } else if (signatureValid) {
            sigText = "Assinatura digital valida";
            sigColor = SUCCESS_COLOR;
        } else {
            sigText = "Assinatura digital invalida";
            sigColor = DANGER_COLOR;
        }
        
        Paragraph sigPara = new Paragraph(sigText, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, sigColor));
        sigPara.setSpacingAfter(15);
        doc.add(sigPara);
    }
    
    private static void addSecurityFindings(Document doc, java.util.List<Heuristics.Finding> findings) throws DocumentException {
        Font h1Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, DARK_GRAY);
        Font h3Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, DARK_GRAY);
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
        Font boldFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10);
        Font monoFont = FontFactory.getFont(FontFactory.COURIER, 8);
        
        addSectionHeader(doc, "ACHADOS DE SEGURANCA", h1Font);
        
        if (findings.isEmpty()) {
            doc.add(new Paragraph("Nenhum padrao suspeito identificado.", normalFont));
            return;
        }
        
        Map<String, java.util.List<Heuristics.Finding>> grouped = new LinkedHashMap<String, java.util.List<Heuristics.Finding>>();
        grouped.put("High", new ArrayList<Heuristics.Finding>());
        grouped.put("Medium", new ArrayList<Heuristics.Finding>());
        grouped.put("Low", new ArrayList<Heuristics.Finding>());
        
        for (Heuristics.Finding f : findings) {
            grouped.get(f.severity).add(f);
        }
        
        int findingNumber = 1;
        for (Map.Entry<String, java.util.List<Heuristics.Finding>> entry : grouped.entrySet()) {
            if (entry.getValue().isEmpty()) continue;
            
            String severity = entry.getKey();
            Color severityColor = "High".equals(severity) ? DANGER_COLOR : 
                                 "Medium".equals(severity) ? WARNING_COLOR : SUCCESS_COLOR;
            
            Paragraph severityHeader = new Paragraph("\n" + severity + " Severity", 
                                                     FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, severityColor));
            severityHeader.setSpacingBefore(10);
            severityHeader.setSpacingAfter(5);
            doc.add(severityHeader);
            
            for (Heuristics.Finding f : entry.getValue()) {
                PdfPTable findingTable = new PdfPTable(1);
                findingTable.setWidthPercentage(100);
                findingTable.setSpacingBefore(5);
                findingTable.setSpacingAfter(5);
                
                PdfPCell headerCell = new PdfPCell();
                headerCell.setBackgroundColor(LIGHT_GRAY);
                headerCell.setPadding(8);
                headerCell.setBorderWidth(0);
                
                Paragraph findingTitle = new Paragraph(String.format("Achado #%d: %s", findingNumber++, f.summary), boldFont);
                headerCell.addElement(findingTitle);
                findingTable.addCell(headerCell);
                
                PdfPCell detailCell = new PdfPCell();
                detailCell.setPadding(8);
                detailCell.setBorderWidth(0);
                detailCell.setBorderColor(LIGHT_GRAY);
                detailCell.setBorder(Rectangle.LEFT | Rectangle.RIGHT | Rectangle.BOTTOM);
                
                Paragraph detail = new Paragraph(f.detail, monoFont);
                detail.setSpacingAfter(5);
                detailCell.addElement(detail);
                
                if (f.attackId != null && !f.attackId.isEmpty()) {
                    Paragraph mitre = new Paragraph(
                        String.format("MITRE ATT&CK: %s - %s", f.attackId, safe(f.attackTactic)),
                        FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8, PRIMARY_COLOR)
                    );
                    detailCell.addElement(mitre);
                }
                
                findingTable.addCell(detailCell);
                doc.add(findingTable);
            }
        }
    }
    
    private static void addNetworkAnalysis(Document doc, EvidencePackage ev) throws DocumentException {
        Font h1Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, DARK_GRAY);
        Font h3Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, DARK_GRAY);
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
        Font monoFont = FontFactory.getFont(FontFactory.COURIER, 8);
        
        addSectionHeader(doc, "ANALISE DE REDE", h1Font);
        
        if (ev.Connections.isEmpty()) {
            doc.add(new Paragraph("Nenhuma conexao de rede ativa identificada.", normalFont));
            return;
        }
        
        addSubsectionHeader(doc, String.format("Total de Conexoes: %d", ev.Connections.size()), h3Font);
        
        PdfPTable connTable = new PdfPTable(new float[]{0.8f, 1.5f, 0.7f, 1.5f, 0.8f, 1f});
        connTable.setWidthPercentage(100);
        connTable.setSpacingBefore(10);
        connTable.setHeaderRows(1);
        
        addTableHeader(connTable, "PID");
        addTableHeader(connTable, "Processo");
        addTableHeader(connTable, "Protocolo");
        addTableHeader(connTable, "Destino");
        addTableHeader(connTable, "Estado");
        addTableHeader(connTable, "Geolocalizacao");
        
        int connCount = 0;
        for (ConnectionInfo c : ev.Connections) {
            if (!"127.0.0.1".equals(c.RemoteAddress) && !"::1".equals(c.RemoteAddress)) {
                String country = Geo.country(c.RemoteAddress);
                String asn = Geo.asn(c.RemoteAddress);
                String geo = String.format("%s %s", safe(country), safe(asn)).trim();
                
                addTableCell(connTable, String.valueOf(c.Pid), monoFont);
                addTableCell(connTable, safe(c.ProcessName), monoFont);
                addTableCell(connTable, String.format("%s/%s", c.Protocol, safe(c.AddressFamily)), monoFont);
                addTableCell(connTable, String.format("%s:%d", c.RemoteAddress, c.RemotePort), monoFont);
                addTableCell(connTable, c.State, monoFont);
                addTableCell(connTable, geo.isEmpty() ? "-" : geo, monoFont);
                
                if (++connCount >= 50) break;
            }
        }
        
        doc.add(connTable);
    }
    
    private static void addPersistenceMechanisms(Document doc, EvidencePackage ev) throws DocumentException {
        Font h1Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, DARK_GRAY);
        Font h3Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, DARK_GRAY);
        Font monoFont = FontFactory.getFont(FontFactory.COURIER, 8);
        
        addSectionHeader(doc, "MECANISMOS DE PERSISTENCIA", h1Font);
        
        if (!ev.Registry.RunKeys.isEmpty()) {
            addSubsectionHeader(doc, String.format("Run Keys (%d)", ev.Registry.RunKeys.size()), h3Font);
            
            PdfPTable runTable = new PdfPTable(new float[]{1.5f, 1f, 3f});
            runTable.setWidthPercentage(100);
            runTable.setSpacingBefore(10);
            runTable.setSpacingAfter(15);
            runTable.setHeaderRows(1);
            
            addTableHeader(runTable, "Hive");
            addTableHeader(runTable, "Nome");
            addTableHeader(runTable, "Valor");
            
            for (RunKeyEntry r : ev.Registry.RunKeys) {
                addTableCell(runTable, r.Hive, monoFont);
                addTableCell(runTable, r.Name, monoFont);
                addTableCell(runTable, r.Value, monoFont);
            }
            
            doc.add(runTable);
        }
        
        if (ev.ScheduledTasks != null && !ev.ScheduledTasks.isEmpty()) {
            addSubsectionHeader(doc, String.format("Tarefas Agendadas (%d)", ev.ScheduledTasks.size()), h3Font);
            
            PdfPTable taskTable = new PdfPTable(new float[]{2f, 1f, 3f});
            taskTable.setWidthPercentage(100);
            taskTable.setSpacingBefore(10);
            taskTable.setSpacingAfter(15);
            taskTable.setHeaderRows(1);
            
            addTableHeader(taskTable, "Nome");
            addTableHeader(taskTable, "Status");
            addTableHeader(taskTable, "Executavel");
            
            for (ScheduledTaskEntry t : ev.ScheduledTasks) {
                addTableCell(taskTable, t.TaskPath, monoFont);
                addTableCell(taskTable, t.Enabled ? "Habilitado" : "Desabilitado", monoFont);
                addTableCell(taskTable, String.format("%s %s", t.ExecPath, safe(t.Arguments)), monoFont);
            }
            
            doc.add(taskTable);
        }
    }
    
    private static void addProcessAnalysis(Document doc, EvidencePackage ev) throws DocumentException {
        Font h1Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, DARK_GRAY);
        Font h3Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, DARK_GRAY);
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
        Font monoFont = FontFactory.getFont(FontFactory.COURIER, 8);
        
        addSectionHeader(doc, "ANALISE DE PROCESSOS", h1Font);
        
        addSubsectionHeader(doc, String.format("Total de Processos: %d", ev.Processes.size()), h3Font);
        
        PdfPTable procTable = new PdfPTable(new float[]{0.8f, 2f, 3f});
        procTable.setWidthPercentage(100);
        procTable.setSpacingBefore(10);
        procTable.setHeaderRows(1);
        
        addTableHeader(procTable, "PID");
        addTableHeader(procTable, "Nome");
        addTableHeader(procTable, "Caminho");
        
        int count = 0;
        for (ProcessInfo p : ev.Processes) {
            addTableCell(procTable, String.valueOf(p.Pid), monoFont);
            addTableCell(procTable, p.Name, monoFont);
            addTableCell(procTable, safe(p.Path), monoFont);
            
            if (++count >= 30) break;
        }
        
        doc.add(procTable);
    }
    
    private static void addMitreMapping(Document doc, java.util.List<Heuristics.Finding> findings) throws DocumentException {
        Font h1Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, DARK_GRAY);
        Font h3Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, DARK_GRAY);
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
        
        addSectionHeader(doc, "MAPEAMENTO MITRE ATT&CK", h1Font);
        
        Map<String, java.util.List<String>> tacticsMap = new LinkedHashMap<String, java.util.List<String>>();
        
        for (Heuristics.Finding f : findings) {
            if (f.attackTactic != null && !f.attackTactic.isEmpty()) {
                if (!tacticsMap.containsKey(f.attackTactic)) {
                    tacticsMap.put(f.attackTactic, new ArrayList<String>());
                }
                String technique = String.format("%s - %s", safe(f.attackId), f.summary);
                if (!tacticsMap.get(f.attackTactic).contains(technique)) {
                    tacticsMap.get(f.attackTactic).add(technique);
                }
            }
        }
        
        if (tacticsMap.isEmpty()) {
            doc.add(new Paragraph("Nenhuma tecnica MITRE ATT&CK mapeada.", normalFont));
            return;
        }
        
        for (Map.Entry<String, java.util.List<String>> entry : tacticsMap.entrySet()) {
            Paragraph tacticHeader = new Paragraph("\n" + entry.getKey(), h3Font);
            tacticHeader.setSpacingBefore(10);
            tacticHeader.setSpacingAfter(5);
            doc.add(tacticHeader);
            
            com.lowagie.text.List list = new com.lowagie.text.List(com.lowagie.text.List.UNORDERED);
            list.setListSymbol("*");
            list.setIndentationLeft(20);
            
            for (String technique : entry.getValue()) {
                list.add(new ListItem(technique, normalFont));
            }
            
            doc.add(list);
        }
    }
    
    // Helper methods
    private static void addSectionHeader(Document doc, String text, Font font) throws DocumentException {
        Paragraph header = new Paragraph(text, font);
        header.setSpacingBefore(5);
        header.setSpacingAfter(10);
        doc.add(header);
        
        PdfPTable line = new PdfPTable(1);
        line.setWidthPercentage(100);
        line.setSpacingAfter(15);
        PdfPCell cell = new PdfPCell();
        cell.setBackgroundColor(PRIMARY_COLOR);
        cell.setFixedHeight(2);
        cell.setBorder(0);
        line.addCell(cell);
        doc.add(line);
    }
    
    private static void addSubsectionHeader(Document doc, String text, Font font) throws DocumentException {
        Paragraph header = new Paragraph(text, font);
        header.setSpacingBefore(10);
        header.setSpacingAfter(5);
        doc.add(header);
    }
    
    private static void addInfoRow(PdfPTable table, String label, String value, Font boldFont, Font normalFont) {
        PdfPCell labelCell = new PdfPCell(new Phrase(label, boldFont));
        labelCell.setBackgroundColor(LIGHT_GRAY);
        labelCell.setPadding(8);
        labelCell.setBorder(0);
        table.addCell(labelCell);
        
        PdfPCell valueCell = new PdfPCell(new Phrase(value, normalFont));
        valueCell.setPadding(8);
        valueCell.setBorder(0);
        table.addCell(valueCell);
    }
    
    private static void addStatRow(PdfPTable table, String label, String value, Color color) {
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
        
        PdfPCell labelCell = new PdfPCell(new Phrase(label, normalFont));
        labelCell.setPadding(8);
        labelCell.setBorderColor(LIGHT_GRAY);
        table.addCell(labelCell);
        
        PdfPCell valueCell = new PdfPCell(new Phrase(value, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, color)));
        valueCell.setPadding(8);
        valueCell.setBorderColor(LIGHT_GRAY);
        valueCell.setHorizontalAlignment(Element.ALIGN_CENTER);
        table.addCell(valueCell);
    }
    
    private static void addTableHeader(PdfPTable table, String text) {
        PdfPCell header = new PdfPCell(new Phrase(text, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.WHITE)));
        header.setBackgroundColor(DARK_GRAY);
        header.setPadding(5);
        header.setHorizontalAlignment(Element.ALIGN_CENTER);
        table.addCell(header);
    }
    
    private static void addTableCell(PdfPTable table, String text, Font font) {
        PdfPCell cell = new PdfPCell(new Phrase(text, font));
        cell.setPadding(4);
        cell.setBorderColor(LIGHT_GRAY);
        table.addCell(cell);
    }
    
    private static String calculateRiskLevel(java.util.List<Heuristics.Finding> findings) {
        int high = 0, medium = 0;
        for (Heuristics.Finding f : findings) {
            if ("High".equals(f.severity)) high++;
            else if ("Medium".equals(f.severity)) medium++;
        }
        
        if (high >= 3) return "CRITICO";
        if (high >= 1) return "ALTO";
        if (medium >= 3) return "MEDIO";
        return "BAIXO";
    }
    
    private static Color getRiskColor(String level) {
        switch (level) {
            case "CRITICO": return DANGER_COLOR;
            case "ALTO": return new Color(230, 126, 34);
            case "MEDIO": return WARNING_COLOR;
            default: return SUCCESS_COLOR;
        }
    }
    
    private static String safe(String s) {
        return s == null || s.isEmpty() ? "-" : s;
    }
    
    static class HeaderFooter extends PdfPageEventHelper {
        @Override
        public void onEndPage(PdfWriter writer, Document document) {
            Font smallFont = FontFactory.getFont(FontFactory.HELVETICA, 8, Color.GRAY);
            PdfContentByte cb = writer.getDirectContent();
            
            Phrase header = new Phrase("DFIR Forensic Analysis Report - CONFIDENCIAL", smallFont);
            ColumnText.showTextAligned(cb, Element.ALIGN_CENTER,
                    header,
                    (document.right() - document.left()) / 2 + document.leftMargin(),
                    document.top() + 20, 0);
            
            Phrase footer = new Phrase(String.format("Pagina %d", writer.getPageNumber()), smallFont);
            ColumnText.showTextAligned(cb, Element.ALIGN_CENTER,
                    footer,
                    (document.right() - document.left()) / 2 + document.leftMargin(),
                    document.bottom() - 20, 0);
        }
    }
}

