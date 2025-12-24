package com.dfir.analyzer;

import java.io.*;
import java.nio.charset.StandardCharsets;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PackageReader {
    private static final byte VERSION = 1;

    public static class Result {
        public final byte[] data;
        public final boolean signaturePresent;
        public final Boolean signatureValid; // null quando não há assinatura
        public Result(byte[] data, boolean signaturePresent, Boolean signatureValid) {
            this.data = data; this.signaturePresent = signaturePresent; this.signatureValid = signatureValid;
        }
    }

    public static Result readAndDecrypt(File pkg, String password) throws Exception {
        try (DataInputStream dis = new DataInputStream(new FileInputStream(pkg))) {
            byte[] magic = dis.readNBytes(4);
            if (!new String(magic, StandardCharsets.US_ASCII).equals("FPKG"))
                throw new IllegalArgumentException("Pacote inválido");
            byte version = dis.readByte();
            if (version != VERSION) throw new IllegalArgumentException("Versão não suportada: " + version);
            byte[] salt = dis.readNBytes(16);
            byte[] nonce = dis.readNBytes(12);
            byte[] lenBytes = dis.readNBytes(4);
            int len = java.nio.ByteBuffer.wrap(lenBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
            byte[] cipher = dis.readNBytes(len);
            // Check for optional signature appended: [sigLen 4 LE][sig]
            boolean hasSig = false;
            byte[] sigBytes = null;
            if (dis.available() >= 4) {
                byte[] sLenBytes = dis.readNBytes(4);
                if (sLenBytes.length == 4) {
                    int sLen = java.nio.ByteBuffer.wrap(sLenBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
                    if (sLen > 0 && dis.available() >= sLen) {
                        sigBytes = dis.readNBytes(sLen);
                        hasSig = true;
                    }
                }
            }

            boolean unencrypted = isAllZero(salt) && isAllZero(nonce);
            if (unencrypted) {
                // If HMAC appended, verify and strip
                if (cipher.length >= 32) {
                    byte[] data = java.util.Arrays.copyOf(cipher, cipher.length - 32);
                    byte[] tag = java.util.Arrays.copyOfRange(cipher, cipher.length - 32, cipher.length);
                    byte[] calc = hmacSha256(data, password);
                    if (java.util.Arrays.equals(tag, calc)) return new Result(data, hasSig, verifyCms(sigBytes));
                    // Fallback: if trimmed data looks like JSON (ends with '}' or ']'), use it
                    if (data.length > 0) {
                        int last = data[data.length - 1] & 0xFF;
                        if (last == '}' || last == ']') return new Result(data, hasSig, verifyCms(sigBytes));
                    }
                }
                return new Result(cipher, hasSig, verifyCms(sigBytes));
            }

            // Signature, if present, is ignored for analysis

            SecretKey key = deriveKey(password, salt, 32);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
            c.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] plain = c.doFinal(cipher);
            return new Result(plain, hasSig, verifyCms(sigBytes));
        }
    }

    private static Boolean verifyCms(byte[] sigBytes) {
        if (sigBytes == null || sigBytes.length == 0) return null; // sem assinatura
        try {
            org.bouncycastle.cms.CMSSignedData cms = new org.bouncycastle.cms.CMSSignedData(sigBytes);
            org.bouncycastle.cms.SignerInformationStore signers = cms.getSignerInfos();
            java.util.Collection<org.bouncycastle.cms.SignerInformation> col = signers.getSigners();

            org.bouncycastle.util.Store<?> certStore = cms.getCertificates();
            for (org.bouncycastle.cms.SignerInformation s : col) {
                @SuppressWarnings("unchecked")
                java.util.Collection<org.bouncycastle.cert.X509CertificateHolder> certs = (java.util.Collection<org.bouncycastle.cert.X509CertificateHolder>) certStore.getMatches(null);
                for (org.bouncycastle.cert.X509CertificateHolder holder : certs) {
                    java.security.cert.X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(holder);
                    org.bouncycastle.cms.SignerInformationVerifier siv = new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder().build(cert);
                    if (s.verify(siv)) {
                        return true; // ao menos um signer válido
                    }
                }
            }
            return false; // assinatura presente mas não verificada
        } catch (Exception e) {
            return false; // erro ao verificar conta como inválida
        }
    }

    private static SecretKey deriveKey(String password, byte[] salt, int size) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100_000, size * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return new SecretKeySpec(skf.generateSecret(spec).getEncoded(), "AES");
    }

    private static boolean isAllZero(byte[] arr) {
        for (byte b : arr) if (b != 0) return false;
        return true;
    }

    private static byte[] hmacSha256(byte[] data, String password) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] key = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    // CMS signature verification not implemented in this build
}
