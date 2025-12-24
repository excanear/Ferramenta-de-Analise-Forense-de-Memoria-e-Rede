<div align="center">

# 🔍 DFIR Forensics Toolkit
### Ferramenta de Análise Forense de Memória e Rede

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Java](https://img.shields.io/badge/Java-17-ED8B00?logo=openjdk)](https://openjdk.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows)](https://www.microsoft.com/windows)

**Solução profissional completa para análise forense digital, resposta a incidentes e detecção de ameaças em ambientes Windows**

[Recursos](#-recursos-principais) • [Instalação](#-instalação-rápida) • [Uso](#-uso) • [Documentação](#-documentação) • [Contribuir](#-contribuindo)

</div>

---

## 📖 Sobre o Projeto

**DFIR Forensics Toolkit** é uma solução completa de análise forense digital e resposta a incidentes (Digital Forensics & Incident Response) desenvolvida para profissionais de segurança cibernética. A ferramenta combina um **coletor avançado em C#** com interface gráfica moderna e um **analisador inteligente em Java**, proporcionando uma abordagem end-to-end para investigação de sistemas Windows comprometidos.

### 🎯 Casos de Uso

- ✅ **Resposta a Incidentes**: Coleta rápida de evidências voláteis durante investigações
- ✅ **Threat Hunting**: Identificação proativa de indicadores de comprometimento (IOCs)
- ✅ **Análise de Malware**: Detecção de persistência e comportamentos suspeitos
- ✅ **Compliance e Auditoria**: Documentação técnica detalhada em formato PDF
- ✅ **Investigações Corporativas**: Análise de processos, conexões e configurações do sistema

---

## ⚡ Recursos Principais

### 🖥️ Coletor Forense (C# - WPF)

- **Interface Gráfica Moderna**: Aplicação WPF intuitiva com modo GUI e CLI
- **Coleta Seletiva de Evidências**:
  - 🔹 Processos em execução (com detecção de rootkits básica)
  - 🔹 Conexões de rede ativas (TCP/UDP, IPv4/IPv6)
  - 🔹 Chaves de registro de persistência (Run Keys, Services, etc.)
  - 🔹 Tarefas agendadas (Scheduled Tasks)
  - 🔹 Persistências WMI (Event Consumers)
  - 🔹 Programas de inicialização (Startup)
  - 🔹 IFEO (Image File Execution Options)
  - 🔹 AppInit_DLLs

- **Segurança de Dados**:
  - 🔐 Criptografia AES-256-GCM com PBKDF2 (100.000 iterações)
  - 🔏 HMAC-SHA256 para verificação de integridade
  - ✍️ Assinatura digital CMS (Authenticode)
  - 🗜️ Compactação automática de evidências

### 📊 Analisador Forense (Java)

- **Heurísticas Avançadas de Detecção**:
  - 🚨 Processos sem janela com conexões externas suspeitas
  - 🚨 Persistências em diretórios não padrão (AppData, Temp, Users)
  - 🚨 Serviços com inicialização automática suspeita
  - 🚨 Detecção de processos potencialmente ocultos

- **Relatórios Profissionais**:
  - 📄 Relatório PDF detalhado com análise completa
  - 🗺️ Mapeamento MITRE ATT&CK com táticas e técnicas
  - 🌐 DNS reverso e geolocalização de IPs (País/ASN/Org)
  - 📋 Exportação de IOCs em JSON e CSV

- **Recursos Adicionais**:
  - 🔍 Validação de assinaturas digitais (CMS)
  - 🌐 Modo offline (`--no-network`) para ambientes isolados
  - 📑 Exportação automática de indicadores de comprometimento

---

## 🚀 Instalação Rápida

### Pré-requisitos

| Componente | Versão | Uso |
|-----------|---------|-----|
| **Windows** | 10/11 (64-bit) | Sistema operacional |
| **.NET SDK** | 8.0+ | Compilar coletor |
| **Java JDK** | 17+ | Compilar analisador |
| **Maven** | 3.6+ | Build do Java |

### Compilação

#### 1️⃣ Coletor (C#)
```powershell
cd collector-cs
dotnet build -c Release
```
📦 Executável gerado: `collector-cs\bin\Release\net8.0-windows\ForensicCollector.exe`

#### 2️⃣ Analisador (Java)
```powershell
cd analyzer-java
mvn clean package -DskipTests
```
📦 JAR gerado: `analyzer-java\target\analyzer.jar`

#### 3️⃣ Build Self-Contained (Opcional)
```powershell
cd collector-cs
dotnet publish -c Release -r win-x64 --self-contained true `
  /p:PublishSingleFile=true `
  /p:DebugType=none `
  /p:IncludeNativeLibrariesForSelfExtract=true
```
📦 Executável único: `collector-cs\bin\Release\net8.0-windows\win-x64\publish\ForensicCollector.exe`

---

## 💡 Uso

### 🖱️ Modo Interface Gráfica (Recomendado)

Execute o coletor sem argumentos para abrir a interface WPF:

```powershell
.\ForensicCollector.exe
```

**Interface WPF inclui:**
- ✨ Seleção visual de evidências a coletar
- ✨ Configuração de senha e caminho de saída
- ✨ Opções de assinatura digital e criptografia
- ✨ Console de log em tempo real
- ✨ Integração com analisador Java

### ⌨️ Modo Linha de Comando

#### Coleta de Evidências
```powershell
# Coleta completa com criptografia
.\ForensicCollector.exe C:\Evidencias\caso001.fpkg "SenhaForte@123" --json

# Coleta sem criptografia + HMAC (integridade)
.\ForensicCollector.exe C:\Evidencias\caso001.fpkg "SenhaForte@123" --json --no-encrypt --hmac

# Coleta com assinatura digital
.\ForensicCollector.exe C:\Evidencias\caso001.fpkg "SenhaForte@123" --json `
  --sign --pfx C:\Certs\forensic.pfx --pfx-pass "PfxPassword"
```

**Opções Disponíveis:**
- `--json`: Formato de saída JSON
- `--no-encrypt`: Desabilitar criptografia AES-GCM
- `--hmac`: Adicionar HMAC-SHA256 (modo sem criptografia)
- `--sign`: Assinar pacote com certificado digital
- `--pfx <arquivo>`: Caminho do certificado PFX
- `--pfx-pass <senha>`: Senha do certificado
- `--log <arquivo>`: Arquivo de log customizado
- `--log-level <off|warn|info>`: Nível de log

#### Análise e Geração de Relatório
```powershell
# Análise padrão com consultas de rede
java -jar analyzer.jar C:\Evidencias\caso001.fpkg "SenhaForte@123" C:\Relatorios\relatorio.pdf

# Análise offline + exportação de IOCs
java -jar analyzer.jar C:\Evidencias\caso001.fpkg "SenhaForte@123" C:\Relatorios\relatorio.pdf `
  --no-network `
  --ioc-json C:\IOCs\iocs.json `
  --ioc-csv C:\IOCs\iocs.csv
```

**Opções do Analisador:**
- `--no-network`: Modo offline (sem DNS reverso/WHOIS)
- `--ioc-json <arquivo>`: Exportar IOCs em JSON
- `--ioc-csv <arquivo>`: Exportar IOCs em CSV

---

## 📋 Heurísticas de Detecção

| Heurística | Severidade | Descrição |
|-----------|-----------|-----------|
| **Processo sem janela + conexão externa** | 🔴 Alta | Processo oculto conectando para IP externo em porta não padrão |
| **Conexões externas suspeitas** | 🟡 Média | Conexões para IPs/portas incomuns |
| **Persistência em diretórios suspeitos** | 🟡 Média | Run Keys apontando para AppData/Temp/Users |
| **Serviços com auto-start suspeito** | 🔴 Alta | Serviços com `StartType=Auto` em diretórios não confiáveis |
| **Processos potencialmente ocultos** | 🔴 Alta | Discrepância entre NtQuerySystemInformation e API gerenciada |

---

## 🔒 Segurança e Integridade

### Criptografia
- **Algoritmo**: AES-256-GCM (Galois/Counter Mode)
- **Derivação de Chave**: PBKDF2 com 100.000 iterações
- **Salt**: Aleatório de 128 bits por pacote
- **Nonce**: Aleatório de 96 bits (padrão GCM)

### Assinatura Digital
- **Padrão**: CMS (Cryptographic Message Syntax) / PKCS#7
- **Validação**: Verificação automática no relatório PDF
- **Suporte**: Certificados X.509 (PFX/P12)

### Garantias
- ✅ **Não destrutivo**: Apenas leitura, sem alterações no sistema
- ✅ **Chain of Custody**: Assinatura digital garante autenticidade
- ✅ **Integridade**: HMAC-SHA256 detecta adulterações
- ✅ **Confidencialidade**: AES-256 protege dados sensíveis

---

## 🗺️ Mapeamento MITRE ATT&CK

A ferramenta mapeia automaticamente achados para o framework MITRE ATT&CK:

| Técnica | ID | Tática |
|---------|-----|--------|
| Registry Run Keys / Startup Folder | T1547.001 | Persistence |
| Scheduled Task/Job | T1053.005 | Persistence, Execution |
| Windows Management Instrumentation | T1047 | Execution |
| Image File Execution Options Injection | T1546.012 | Persistence, Privilege Escalation |
| AppInit DLLs | T1546.010 | Persistence, Privilege Escalation |
| Hidden Window | T1564.003 | Defense Evasion |

---

## 📚 Documentação

### Estrutura do Projeto
```
DFIR-Toolkit/
├── collector-cs/              # Coletor C# (WPF)
│   ├── src/
│   │   ├── UI/               # Interface gráfica
│   │   │   ├── MainWindow.xaml
│   │   │   └── MainWindow.xaml.cs
│   │   ├── Collectors/       # Módulos de coleta
│   │   ├── Models/           # Modelos de dados
│   │   └── Security/         # Criptografia/Assinatura
│   └── ForensicCollector.csproj
├── analyzer-java/             # Analisador Java
│   ├── src/main/java/com/dfir/analyzer/
│   │   ├── EvidenceAnalyzer.java
│   │   ├── PdfReportGenerator.java
│   │   └── ...
│   └── pom.xml
└── scripts/                   # Scripts auxiliares
    └── sign-exe.ps1          # Assinatura Authenticode
```

### Formato do Pacote Forense

```
┌─────────────────────────────────┐
│ Header (8 bytes)                │  "FPKG\x01\x00" + flags
├─────────────────────────────────┤
│ Salt (16 bytes)                 │  PBKDF2 salt
├─────────────────────────────────┤
│ Nonce (12 bytes)                │  AES-GCM nonce
├─────────────────────────────────┤
│ Encrypted JSON Data             │  Evidências criptografadas
├─────────────────────────────────┤
│ GCM Auth Tag (16 bytes)         │  Tag de autenticação
├─────────────────────────────────┤
│ [Opcional] HMAC (32 bytes)      │  SHA-256 HMAC
├─────────────────────────────────┤
│ [Opcional] CMS Signature        │  Assinatura digital
└─────────────────────────────────┘
```

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Para contribuir:

1. 🍴 Fork o projeto
2. 🌿 Crie uma branch para sua feature (`git checkout -b feature/MinhaFeature`)
3. 💾 Commit suas mudanças (`git commit -m 'Adiciona MinhaFeature'`)
4. 📤 Push para a branch (`git push origin feature/MinhaFeature`)
5. 🔃 Abra um Pull Request

### Diretrizes de Contribuição
- ✅ Código deve seguir as convenções de estilo do projeto
- ✅ Adicione testes para novas funcionalidades
- ✅ Atualize a documentação conforme necessário
- ✅ Mantenha commits atômicos e bem descritos

---

## 📄 Licença

Este projeto está licenciado sob a **Licença MIT** - veja o arquivo [LICENSE](LICENSE) para detalhes.

```
MIT License

Copyright (c) 2025 Escanearcpl

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 👨‍💻 Autor

<div align="center">

### **Escanearcpl**

[![GitHub](https://img.shields.io/badge/GitHub-@Escanearcpl-181717?logo=github)](https://github.com/excanear)
[![Portfolio](https://img.shields.io/badge/Portfolio-Escanearcpl-4285F4?logo=google-chrome)](https://github.com/excanear)

**Desenvolvido com ❤️ para a comunidade de segurança cibernética**

</div>

---

## ⚠️ Aviso Legal

Esta ferramenta é destinada **exclusivamente para uso legítimo** em:
- ✅ Investigações forenses autorizadas
- ✅ Resposta a incidentes de segurança
- ✅ Pesquisa e educação em segurança cibernética
- ✅ Auditorias e testes de conformidade

**⚠️ O uso indevido desta ferramenta pode violar leis locais e internacionais. O autor não se responsabiliza por uso inadequado ou ilegal.**

---

## 📞 Suporte

- 📧 **Contato**: Entre em contato via GitHub

---

<div align="center">

### ⭐ Se este projeto foi útil, considere dar uma estrela!

**DFIR Forensics Toolkit** • v1.0.0 • © 2025 Escanearcpl

</div>
