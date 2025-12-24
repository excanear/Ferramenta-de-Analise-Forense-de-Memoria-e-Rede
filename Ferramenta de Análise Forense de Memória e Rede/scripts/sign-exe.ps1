param(
    [Parameter(Mandatory=$true)] [string]$ExePath,
    [Parameter(Mandatory=$true)] [string]$PfxPath,
    [Parameter(Mandatory=$false)] [string]$PfxPass,
    [Parameter(Mandatory=$false)] [string]$TimestampUrl = "http://timestamp.digicert.com"
)

Write-Host "Assinando executável:" $ExePath
if (!(Test-Path -LiteralPath $ExePath)) { throw "Executável não encontrado: $ExePath" }
if (!(Test-Path -LiteralPath $PfxPath)) { throw "PFX não encontrado: $PfxPath" }

$signTool = Get-Command signtool -ErrorAction SilentlyContinue
if ($null -eq $signTool) {
    Write-Warning "signtool.exe não encontrado. Instale o Windows SDK (Build Tools) para obter o SignTool."
    Write-Host "Download: https://developer.microsoft.com/windows/downloads/windows-sdk/"
    return
}

$cmd = @(
    'sign', '/fd', 'sha256', '/td', 'sha256', '/tr', $TimestampUrl,
    '/f', $PfxPath
)
if ($PfxPass) { $cmd += @('/p', $PfxPass) }
$cmd += @('/v', $ExePath)

& $signTool.Path $cmd
if ($LASTEXITCODE -ne 0) { throw "Falha ao assinar o executável (código $LASTEXITCODE)." }

Write-Host "Executável assinado com sucesso."