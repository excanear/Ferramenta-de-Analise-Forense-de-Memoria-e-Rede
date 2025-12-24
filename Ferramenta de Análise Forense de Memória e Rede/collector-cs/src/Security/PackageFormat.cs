using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ForensicCollector.Security;

public static class PackageFormat
{
    // Simple binary format: [magic 4 bytes 'FPKG'][version 1 byte][salt 16][nonce 12][cipherLen 4][cipher]
    private const string Magic = "FPKG";
    private const byte Version = 1;

    public static byte[] EncryptAndWrap(byte[] plaintext, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] key = DeriveKey(password, salt, 32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] cipher = AesGcmEncrypt(plaintext, key, nonce);
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write(Encoding.ASCII.GetBytes(Magic));
        bw.Write(Version);
        bw.Write(salt);
        bw.Write(nonce);
        bw.Write(BitConverter.GetBytes(cipher.Length));
        bw.Write(cipher);
        return ms.ToArray();
    }

    public static byte[] WrapUnencrypted(byte[] plaintext, string? password = null, bool useHmac = false)
    {
        // No encryption: salt/nonce zeroed, cipher is plaintext
        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];
        byte[] payload = plaintext;
        if (useHmac)
        {
            byte[] tag = ComputeHmacSha256(plaintext, password);
            payload = plaintext.Concat(tag).ToArray();
        }
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write(Encoding.ASCII.GetBytes(Magic));
        bw.Write(Version);
        bw.Write(salt);
        bw.Write(nonce);
        bw.Write(BitConverter.GetBytes(payload.Length));
        bw.Write(payload);
        return ms.ToArray();
    }

    public static (byte[] salt, byte[] nonce, byte[] cipher) Unwrap(byte[] package)
    {
        using var ms = new MemoryStream(package);
        using var br = new BinaryReader(ms);
        var magic = br.ReadBytes(4);
        if (Encoding.ASCII.GetString(magic) != Magic)
            throw new InvalidDataException("Pacote inválido: magic incorreto");
        byte version = br.ReadByte();
        if (version != Version)
            throw new InvalidDataException($"Versão de pacote não suportada: {version}");
        var salt = br.ReadBytes(16);
        var nonce = br.ReadBytes(12);
        int len = br.ReadInt32();
        var cipher = br.ReadBytes(len);
        return (salt, nonce, cipher);
    }

    public static byte[] Decrypt(byte[] salt, byte[] nonce, byte[] cipher, string password)
    {
        byte[] key = DeriveKey(password, salt, 32);
        return AesGcmDecrypt(cipher, key, nonce);
    }

    private static byte[] DeriveKey(string password, byte[] salt, int keySize)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(keySize);
    }

    private static byte[] AesGcmEncrypt(byte[] plaintext, byte[] key, byte[] nonce)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        // Append tag to ciphertext
        return ciphertext.Concat(tag).ToArray();
    }

    private static byte[] AesGcmDecrypt(byte[] cipherWithTag, byte[] key, byte[] nonce)
    {
        int cipherLen = cipherWithTag.Length - 16;
        byte[] ciphertext = cipherWithTag.AsSpan(0, cipherLen).ToArray();
        byte[] tag = cipherWithTag.AsSpan(cipherLen, 16).ToArray();
        byte[] plaintext = new byte[cipherLen];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    private static byte[] ComputeHmacSha256(byte[] data, string? password)
    {
        byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(password ?? string.Empty));
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    public static byte[] AppendSignature(byte[] package, string pfxPath, string? pfxPass)
    {
        // Sign the entire package as CMS attached signature
        var cert = new X509Certificate2(File.ReadAllBytes(pfxPath), pfxPass, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        var content = new ContentInfo(package);
        var cms = new SignedCms(content, true);
        var signer = new CmsSigner(cert)
        {
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        cms.ComputeSignature(signer);
        byte[] sig = cms.Encode();
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write(package);
        bw.Write(BitConverter.GetBytes(sig.Length));
        bw.Write(sig);
        return ms.ToArray();
    }
}
