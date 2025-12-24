package com.dfir.analyzer;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class Geo {
    private static final java.util.concurrent.ConcurrentHashMap<String,String> COUNTRY_CACHE = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.concurrent.ConcurrentHashMap<String,String> ASN_CACHE = new java.util.concurrent.ConcurrentHashMap<>();
    public static String country(String ip) {
        if (ip == null || ip.isBlank()) return "";
        if (!NetOptions.isAllowNetwork()) return "";
        String cached = COUNTRY_CACHE.get(ip);
        if (cached != null) return cached;
        if (isPrivate(ip)) return "Private";
        try {
            String referral = whoisQuery("whois.iana.org", ip);
            String server = parseLine(referral, "refer:");
            if (server == null || server.isBlank()) server = "whois.arin.net"; // fallback
            String data = whoisQuery(server.trim(), ip);
            String c = parseLine(data, "country:");
            String out = c == null ? "" : c.trim();
            if (!out.isEmpty()) COUNTRY_CACHE.put(ip, out);
            return out;
        } catch (Exception e) { return ""; }
    }

    public static String asn(String ip) {
        if (ip == null || ip.isBlank()) return "";
        if (!NetOptions.isAllowNetwork()) return "";
        String cached = ASN_CACHE.get(ip);
        if (cached != null) return cached;
        if (isPrivate(ip)) return "";
        try {
            String server = "whois.iana.org";
            String referral = whoisQuery(server, ip);
            String ref = parseLine(referral, "refer:");
            if (ref == null || ref.isBlank()) ref = "whois.arin.net";
            String data = whoisQuery(ref.trim(), ip);
            String org = parseLine(data, "origin:"); // RIPE style
            if (org != null) { ASN_CACHE.put(ip, org.trim()); return org.trim(); }
            String as = parseLine(data, "ASNumber:"); // ARIN style
            String out = as == null ? "" : as.trim();
            if (!out.isEmpty()) ASN_CACHE.put(ip, out);
            return out;
        } catch (Exception e) { return ""; }
    }

    private static String whoisQuery(String host, String query) throws Exception {
        try (Socket s = new Socket(host, 43)) {
            s.setSoTimeout(3000);
            s.getOutputStream().write((query + "\r\n").getBytes(StandardCharsets.UTF_8));
            s.getOutputStream().flush();
            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
            return sb.toString();
        }
    }

    private static String parseLine(String text, String key) {
        if (text == null) return null;
        String[] lines = text.split("\n");
        for (String l : lines) {
            String ll = l.toLowerCase(Locale.ROOT);
            if (ll.startsWith(key)) return l.substring(key.length()).trim();
        }
        return null;
    }

    private static boolean isPrivate(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.isAnyLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress();
        } catch (Exception e) { return false; }
    }
}
