using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using ForensicCollector.Models;
using ForensicCollector.Collectors;
using ForensicCollector.Security;
using ForensicCollector.Util;
using ForensicCollector.UI;

namespace ForensicCollector;

class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        // If no arguments, launch GUI
        if (args.Length == 0)
        {
            var app = new App();
            app.InitializeComponent();
            app.Run();
            return 0;
        }
        
        // CLI mode - set console encoding only when running in CLI
        Console.OutputEncoding = Encoding.UTF8;
        
        if (args.Length < 2 || args.Contains("--help") || args.Contains("-h"))
        {
            Console.WriteLine("Uso: ForensicCollector <arquivo_saida.fpkg> <senha> [--json] [--no-encrypt] [--hmac] [--sign --pfx <file.pfx> --pfx-pass <senhaPfx>] [--log <caminho>] [--log-level <off|warn|info>]");
            Console.WriteLine("      ForensicCollector (sem argumentos para abrir a interface gráfica)");
            Console.WriteLine("");
            Console.WriteLine("Exemplo CLI: ForensicCollector evidencias.fpkg MinhaSenhaForte! --json");
            Console.WriteLine("Exemplo GUI: ForensicCollector");
            return 1;
        }

        string outputPath = args[0];
        string password = args[1];
        bool outputJson = args.Contains("--json");
        bool noEncrypt = args.Contains("--no-encrypt");
        bool useHmac = args.Contains("--hmac");
        bool sign = args.Contains("--sign");
        string? pfxPath = GetArgValue(args, "--pfx");
        string? pfxPass = GetArgValue(args, "--pfx-pass");

        // Logging config
        string? logPath = GetArgValue(args, "--log");
        string? logLevel = GetArgValue(args, "--log-level");
        Logger.Configure(logPath, logLevel);

        Console.WriteLine("Coletando evidências... Isto pode levar alguns segundos.");

            var evidence = new EvidencePackage
        {
            TimestampUtc = DateTime.UtcNow,
            SystemInfo = new SystemInfo
            {
                Hostname = Environment.MachineName,
                Username = Environment.UserName,
                OsVersion = Environment.OSVersion.VersionString
            },
            Processes = ProcessCollector.CollectProcesses(),
            Connections = NetworkCollector.CollectConnections(),
                Registry = RegistryCollector.CollectPersistence(),
                ScheduledTasks = ScheduledTaskCollector.Collect(),
                WmiSubscriptions = WmiPersistenceCollector.Collect(),
                StartupItems = StartupCollector.Collect(),
                IfeoEntries = IfeoCollector.Collect(),
                AppInit = AppInitCollector.Collect()
        };

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        string json = JsonSerializer.Serialize(evidence, jsonOptions);

        if (outputJson)
        {
            var jsonPath = Path.ChangeExtension(outputPath, ".json");
            Directory.CreateDirectory(Path.GetDirectoryName(jsonPath)!);
            File.WriteAllText(jsonPath, json, Encoding.UTF8);
        }

        byte[] data = Encoding.UTF8.GetBytes(json);
        byte[] packageBytes;
        if (noEncrypt)
        {
            packageBytes = PackageFormat.WrapUnencrypted(data, password, useHmac);
        }
        else
        {
            packageBytes = PackageFormat.EncryptAndWrap(data, password);
        }

        if (sign)
        {
            if (string.IsNullOrEmpty(pfxPath) || !File.Exists(pfxPath))
            {
                Console.Error.WriteLine("Assinatura solicitada, mas PFX não encontrado.");
            }
            else
            {
                try
                {
                    packageBytes = PackageFormat.AppendSignature(packageBytes, pfxPath!, pfxPass);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Falha ao assinar pacote: {ex.Message}");
                }
            }
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        File.WriteAllBytes(outputPath, packageBytes);
        Console.WriteLine($"Pacote gerado: {outputPath}");
        return 0;
    }

    static string? GetArgValue(string[] args, string key)
    {
        var idx = Array.IndexOf(args, key);
        if (idx >= 0 && idx + 1 < args.Length) return args[idx + 1];
        return null;
    }
}
