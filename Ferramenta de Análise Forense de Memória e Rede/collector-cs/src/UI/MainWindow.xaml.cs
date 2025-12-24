using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using ForensicCollector.Models;
using ForensicCollector.Collectors;
using ForensicCollector.Security;

namespace ForensicCollector.UI;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        LogMessage("🔷 DFIR Forensic Tool inicializado com sucesso!");
        LogMessage($"📅 Data: {DateTime.Now:dd/MM/yyyy HH:mm:ss}");
        LogMessage($"💻 Sistema: {Environment.OSVersion}");
        LogMessage($"👤 Usuário: {Environment.UserName} @ {Environment.MachineName}");
        LogMessage("");
    }

    private void LogMessage(string message)
    {
        Dispatcher.Invoke(() =>
        {
            LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
            LogTextBox.ScrollToEnd();
        });
    }

    private void SetStatus(string status, bool isProcessing = false)
    {
        Dispatcher.Invoke(() =>
        {
            StatusTextBlock.Text = status;
            ProgressBar.Visibility = isProcessing ? Visibility.Visible : Visibility.Collapsed;
            ProgressBar.IsIndeterminate = isProcessing;
        });
    }

    private void ShowPassword_Changed(object sender, RoutedEventArgs e)
    {
        if (ShowPasswordCheckBox.IsChecked == true)
        {
            PasswordTextBox.Text = PasswordBox.Password;
            PasswordTextBox.Visibility = Visibility.Visible;
            PasswordBox.Visibility = Visibility.Collapsed;
        }
        else
        {
            PasswordBox.Password = PasswordTextBox.Text;
            PasswordBox.Visibility = Visibility.Visible;
            PasswordTextBox.Visibility = Visibility.Collapsed;
        }
    }

    private void SignPackage_Changed(object sender, RoutedEventArgs e)
    {
        SignaturePanel.IsEnabled = SignPackageCheckBox.IsChecked == true;
    }

    private void BrowseOutputPath_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Filter = "Forensic Package|*.fpkg|All Files|*.*",
            DefaultExt = ".fpkg",
            FileName = "evidencias.fpkg"
        };
        if (dialog.ShowDialog() == true)
        {
            OutputPathTextBox.Text = dialog.FileName;
        }
    }

    private void BrowsePfxPath_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Certificate Files|*.pfx;*.p12|All Files|*.*",
            DefaultExt = ".pfx"
        };
        if (dialog.ShowDialog() == true)
        {
            PfxPathTextBox.Text = dialog.FileName;
        }
    }

    private void BrowseInputPackage_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Forensic Package|*.fpkg|All Files|*.*",
            DefaultExt = ".fpkg"
        };
        if (dialog.ShowDialog() == true)
        {
            InputPackageTextBox.Text = dialog.FileName;
        }
    }

    private void BrowseOutputPdf_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Filter = "PDF Files|*.pdf|All Files|*.*",
            DefaultExt = ".pdf",
            FileName = "relatorio_forense.pdf"
        };
        if (dialog.ShowDialog() == true)
        {
            OutputPdfTextBox.Text = dialog.FileName;
        }
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e)
    {
        LogTextBox.Clear();
        LogMessage("🗑️ Log limpo.");
    }

    private async void CollectButton_Click(object sender, RoutedEventArgs e)
    {
        // Capture UI values BEFORE Task.Run
        string outputPath = OutputPathTextBox.Text;
        string password = ShowPasswordCheckBox.IsChecked == true ? PasswordTextBox.Text : PasswordBox.Password;
        bool exportJson = ExportJsonCheckBox.IsChecked == true;
        bool noEncrypt = NoEncryptCheckBox.IsChecked == true;
        bool useHmac = UseHmacCheckBox.IsChecked == true;
        bool sign = SignPackageCheckBox.IsChecked == true;
        string? pfxPath = PfxPathTextBox.Text;
        string? pfxPassword = PfxPasswordBox.Password;
        
        // Capture evidence selection
        bool collectProcesses = CollectProcessesCheckBox.IsChecked == true;
        bool collectConnections = CollectConnectionsCheckBox.IsChecked == true;
        bool collectRegistry = CollectRegistryCheckBox.IsChecked == true;
        bool collectTasks = CollectTasksCheckBox.IsChecked == true;
        bool collectWmi = CollectWmiCheckBox.IsChecked == true;
        bool collectStartup = CollectStartupCheckBox.IsChecked == true;
        bool collectIfeo = CollectIfeoCheckBox.IsChecked == true;
        bool collectAppInit = CollectAppInitCheckBox.IsChecked == true;

        // Validation
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            MessageBox.Show("Por favor, especifique o caminho de saída.", "Validação", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            MessageBox.Show("Por favor, especifique uma senha.", "Validação", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (sign)
        {
            if (string.IsNullOrWhiteSpace(pfxPath) || !File.Exists(pfxPath))
            {
                MessageBox.Show("Por favor, especifique um arquivo PFX válido.", "Validação", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        CollectButton.IsEnabled = false;
        SetStatus("⏳ Coletando evidências...", true);

        try
        {
            await Task.Run(() => PerformCollection(
                outputPath,
                password,
                exportJson,
                noEncrypt,
                useHmac,
                sign,
                pfxPath,
                pfxPassword,
                collectProcesses,
                collectConnections,
                collectRegistry,
                collectTasks,
                collectWmi,
                collectStartup,
                collectIfeo,
                collectAppInit
            ));

            SetStatus("✅ Coleta concluída com sucesso!", false);
            MessageBox.Show($"Evidências coletadas com sucesso!\n\nArquivo: {outputPath}", 
                "Sucesso", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            SetStatus("❌ Erro na coleta", false);
            LogMessage($"❌ ERRO: {ex.Message}");
            MessageBox.Show($"Erro durante a coleta:\n{ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            CollectButton.IsEnabled = true;
        }
    }

    private void PerformCollection(string outputPath, string password, bool exportJson, 
        bool noEncrypt, bool useHmac, bool sign, string? pfxPath, string? pfxPassword,
        bool collectProcesses, bool collectConnections, bool collectRegistry,
        bool collectTasks, bool collectWmi, bool collectStartup, bool collectIfeo, bool collectAppInit)
    {
        LogMessage("═══════════════════════════════════════════");
        LogMessage("🚀 INICIANDO COLETA DE EVIDÊNCIAS FORENSES");
        LogMessage("═══════════════════════════════════════════");
        LogMessage("");

        LogMessage("📋 Coletando informações do sistema...");
        LogMessage($"   • Hostname: {Environment.MachineName}");
        LogMessage($"   • Usuário: {Environment.UserName}");
        LogMessage($"   • OS: {Environment.OSVersion.VersionString}");
        LogMessage("");

        var evidence = new EvidencePackage
        {
            TimestampUtc = DateTime.UtcNow,
            SystemInfo = new SystemInfo
            {
                Hostname = Environment.MachineName,
                Username = Environment.UserName,
                OsVersion = Environment.OSVersion.VersionString
            }
        };

        if (collectProcesses)
        {
            LogMessage("🔍 Coletando processos em execução...");
            evidence.Processes = ProcessCollector.CollectProcesses();
            LogMessage($"   ✅ {evidence.Processes.Count} processos coletados");
        }
        else
        {
            LogMessage("⏭️ Pulando coleta de processos (desabilitado)");
        }

        if (collectConnections)
        {
            LogMessage("🌐 Coletando conexões de rede...");
            evidence.Connections = NetworkCollector.CollectConnections();
            LogMessage($"   ✅ {evidence.Connections.Count} conexões coletadas");
        }
        else
        {
            LogMessage("⏭️ Pulando coleta de conexões (desabilitado)");
        }

        if (collectRegistry)
        {
            LogMessage("📝 Coletando entradas de registro...");
            evidence.Registry = RegistryCollector.CollectPersistence();
            int regCount = evidence.Registry.RunKeys.Count + evidence.Registry.Services.Count;
            LogMessage($"   ✅ {regCount} entradas coletadas");
        }
        else
        {
            LogMessage("⏭️ Pulando coleta de registro (desabilitado)");
        }

        if (collectTasks)
        {
            LogMessage("⏰ Coletando tarefas agendadas...");
            evidence.ScheduledTasks = ScheduledTaskCollector.Collect();
            LogMessage($"   ✅ {evidence.ScheduledTasks.Count} tarefas coletadas");
        }
        else
        {
            LogMessage("⏭️ Pulando coleta de tarefas (desabilitado)");
        }

        if (collectWmi)
        {
            LogMessage("📡 Coletando assinaturas WMI...");
            evidence.WmiSubscriptions = WmiPersistenceCollector.Collect();
            LogMessage($"   ✅ {evidence.WmiSubscriptions.Count} assinaturas coletadas");
        }
        else
        {
            LogMessage("⏭️ Pulando coleta de WMI (desabilitado)");
        }

        if (collectStartup)
        {
            LogMessage("🚀 Coletando itens de startup...");
            evidence.StartupItems = StartupCollector.Collect();
            LogMessage($"   ✅ {evidence.StartupItems.Count} itens coletados");
        }
        else
        {
            LogMessage("⏭️ Pulando coleta de startup (desabilitado)");
        }

        if (collectIfeo)
        {
            LogMessage("🔧 Coletando entradas IFEO...");
            evidence.IfeoEntries = IfeoCollector.Collect();
            LogMessage($"   ✅ {evidence.IfeoEntries.Count} entradas coletadas");
        }
        else
        {
            LogMessage("⏭️ Pulando coleta de IFEO (desabilitado)");
        }

        if (collectAppInit)
        {
            LogMessage("📚 Coletando AppInit DLLs...");
            evidence.AppInit = AppInitCollector.Collect();
            LogMessage($"   ✅ AppInit configurado: {evidence.AppInit.LoadAppInitDlls}");
        }
        else
        {
            LogMessage("⏭️ Pulando coleta de AppInit (desabilitado)");
        }

        LogMessage("");
        LogMessage("💾 Serializando dados para JSON...");
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        string json = JsonSerializer.Serialize(evidence, jsonOptions);
        LogMessage($"   ✅ JSON gerado ({json.Length:N0} bytes)");

        if (exportJson)
        {
            var jsonPath = Path.ChangeExtension(outputPath, ".json");
            Directory.CreateDirectory(Path.GetDirectoryName(jsonPath)!);
            File.WriteAllText(jsonPath, json, Encoding.UTF8);
            LogMessage($"   💾 JSON exportado: {jsonPath}");
        }

        LogMessage("");
        byte[] data = Encoding.UTF8.GetBytes(json);
        byte[] packageBytes;

        if (noEncrypt)
        {
            LogMessage("🔓 Gerando pacote SEM criptografia (HMAC apenas)...");
            packageBytes = PackageFormat.WrapUnencrypted(data, password, useHmac);
        }
        else
        {
            LogMessage("🔐 Criptografando dados (AES-GCM + PBKDF2)...");
            packageBytes = PackageFormat.EncryptAndWrap(data, password);
        }
        LogMessage($"   ✅ Pacote gerado ({packageBytes.Length:N0} bytes)");

        if (sign && !string.IsNullOrEmpty(pfxPath) && File.Exists(pfxPath))
        {
            try
            {
                LogMessage("✍️ Assinando pacote com certificado digital...");
                packageBytes = PackageFormat.AppendSignature(packageBytes, pfxPath, pfxPassword);
                LogMessage("   ✅ Assinatura CMS anexada");
            }
            catch (Exception ex)
            {
                LogMessage($"   ⚠️ Falha ao assinar: {ex.Message}");
            }
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        File.WriteAllBytes(outputPath, packageBytes);

        LogMessage("");
        LogMessage("═══════════════════════════════════════════");
        LogMessage($"✅ COLETA CONCLUÍDA COM SUCESSO!");
        LogMessage("═══════════════════════════════════════════");
        LogMessage($"📦 Pacote: {outputPath}");
        LogMessage($"📊 Tamanho: {packageBytes.Length / 1024.0:N2} KB");
        LogMessage($"🔐 Criptografia: {(noEncrypt ? "Desabilitada (HMAC)" : "AES-GCM")}");
        LogMessage($"✍️ Assinatura: {(sign ? "Sim" : "Não")}");
        LogMessage("");
    }

    private async void AnalyzeButton_Click(object sender, RoutedEventArgs e)
    {
        // Capture UI values BEFORE Task.Run
        string inputPackage = InputPackageTextBox.Text;
        string password = AnalyzePasswordBox.Password;
        string outputPdf = OutputPdfTextBox.Text;
        bool exportIocJson = ExportIocJsonCheckBox.IsChecked == true;
        string? iocJsonPath = exportIocJson ? IocJsonPathTextBox.Text : null;
        bool exportIocCsv = ExportIocCsvCheckBox.IsChecked == true;
        string? iocCsvPath = exportIocCsv ? IocCsvPathTextBox.Text : null;
        bool offlineMode = OfflineModeCheckBox.IsChecked == true;

        // Validation
        if (string.IsNullOrWhiteSpace(inputPackage) || !File.Exists(inputPackage))
        {
            MessageBox.Show("Por favor, especifique um arquivo de pacote válido.", "Validação", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            MessageBox.Show("Por favor, especifique a senha do pacote.", "Validação", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(outputPdf))
        {
            MessageBox.Show("Por favor, especifique o caminho do PDF de saída.", "Validação", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        AnalyzeButton.IsEnabled = false;
        SetStatus("⏳ Analisando evidências...", true);

        try
        {
            await Task.Run(() => PerformAnalysis(
                inputPackage,
                password,
                outputPdf,
                iocJsonPath,
                iocCsvPath,
                offlineMode
            ));

            SetStatus("✅ Análise concluída com sucesso!", false);
            
            var result = MessageBox.Show($"Análise concluída com sucesso!\n\nRelatório: {outputPdf}\n\nDeseja abrir o relatório?", 
                "Sucesso", MessageBoxButton.YesNo, MessageBoxImage.Information);
            
            if (result == MessageBoxResult.Yes)
            {
                Process.Start(new ProcessStartInfo(outputPdf) { UseShellExecute = true });
            }
        }
        catch (Exception ex)
        {
            SetStatus("❌ Erro na análise", false);
            LogMessage($"❌ ERRO: {ex.Message}");
            MessageBox.Show($"Erro durante a análise:\n{ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            AnalyzeButton.IsEnabled = true;
        }
    }

    private void PerformAnalysis(string packagePath, string password, string pdfPath, 
        string? iocJsonPath, string? iocCsvPath, bool offlineMode)
    {
        LogMessage("═══════════════════════════════════════════");
        LogMessage("🔍 INICIANDO ANÁLISE DE EVIDÊNCIAS");
        LogMessage("═══════════════════════════════════════════");
        LogMessage("");

        // Find Java
        string? javaPath = FindJavaExecutable();
        if (javaPath == null)
        {
            throw new Exception("Java não encontrado. Por favor, instale Java 17 ou superior.");
        }

        LogMessage($"☕ Java encontrado: {javaPath}");

        // Find analyzer JAR
        string analyzerJar = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "..", "..", "..", "..", "analyzer-java", "target", "analyzer.jar");
        
        analyzerJar = Path.GetFullPath(analyzerJar);

        if (!File.Exists(analyzerJar))
        {
            throw new Exception($"Analisador não encontrado em: {analyzerJar}");
        }

        LogMessage($"📦 Analisador: {analyzerJar}");
        LogMessage("");

        // Build command
        var args = new StringBuilder();
        args.Append($"-jar \"{analyzerJar}\" \"{packagePath}\" \"{password}\" \"{pdfPath}\"");

        if (!string.IsNullOrWhiteSpace(iocJsonPath))
        {
            args.Append($" --ioc-json \"{iocJsonPath}\"");
        }

        if (!string.IsNullOrWhiteSpace(iocCsvPath))
        {
            args.Append($" --ioc-csv \"{iocCsvPath}\"");
        }

        if (offlineMode)
        {
            args.Append(" --no-network");
            LogMessage("🔌 Modo offline ativado");
        }

        LogMessage($"🚀 Executando: java {args}");
        LogMessage("");

        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = javaPath,
                Arguments = args.ToString(),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        process.OutputDataReceived += (s, e) => 
        {
            if (!string.IsNullOrWhiteSpace(e.Data))
                LogMessage($"   {e.Data}");
        };

        process.ErrorDataReceived += (s, e) => 
        {
            if (!string.IsNullOrWhiteSpace(e.Data))
                LogMessage($"   ⚠️ {e.Data}");
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new Exception($"Análise falhou com código de saída: {process.ExitCode}");
        }

        LogMessage("");
        LogMessage("═══════════════════════════════════════════");
        LogMessage("✅ ANÁLISE CONCLUÍDA COM SUCESSO!");
        LogMessage("═══════════════════════════════════════════");
        LogMessage($"📄 Relatório PDF: {pdfPath}");
        if (!string.IsNullOrWhiteSpace(iocJsonPath))
            LogMessage($"💾 IOCs JSON: {iocJsonPath}");
        if (!string.IsNullOrWhiteSpace(iocCsvPath))
            LogMessage($"📊 IOCs CSV: {iocCsvPath}");
        LogMessage("");
    }

    private string? FindJavaExecutable()
    {
        // Check JAVA_HOME
        string? javaHome = Environment.GetEnvironmentVariable("JAVA_HOME");
        if (!string.IsNullOrEmpty(javaHome))
        {
            string javaExe = Path.Combine(javaHome, "bin", "java.exe");
            if (File.Exists(javaExe))
                return javaExe;
        }

        // Check common installation paths (JDK 11)
        string[] commonPaths = new[]
        {
            @"C:\java\jdk11\bin\java.exe",
            @"C:\Program Files\Java\jdk-11\bin\java.exe",
            @"C:\Program Files\Eclipse Adoptium\jdk-11\bin\java.exe",
            @"C:\Program Files\Microsoft\jdk-11\bin\java.exe"
        };

        foreach (string path in commonPaths)
        {
            if (File.Exists(path))
                return path;
        }

        // Check PATH
        string? pathVar = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(pathVar))
        {
            foreach (string path in pathVar.Split(';'))
            {
                string javaExe = Path.Combine(path, "java.exe");
                if (File.Exists(javaExe))
                    return javaExe;
            }
        }

        return null;
    }
}
