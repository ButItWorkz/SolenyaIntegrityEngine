<#
.SYNOPSIS
    Solenya Integrity Engine - Environment Configurator
.DESCRIPTION
    An interactive utility to configure the framework for the target environment.
    Injects network routing and PKI infrastructure directly into the Agent and Listener.
    Cryptographically seals API keys using DPAPI to prevent hardcoded secrets.
#>

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "   Solenya Integrity Engine - Environment Setup      " -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

$AgentPath = ".\Agent.ps1"
$ListenerPath = ".\Listener.ps1"

if (-not (Test-Path $AgentPath) -or -not (Test-Path $ListenerPath)) {
    Write-Host "[-] FATAL ERROR: Setup script must be executed from the directory containing Agent.ps1 and Listener.ps1." -ForegroundColor Red
    exit
}

# 1. Configure the Agent Destination
Write-Host "[*] Step 1: Endpoint Routing Configuration" -ForegroundColor Yellow
$TargetIP = Read-Host "Enter the IP Address or FQDN of your Central Server (e.g., 192.168.1.50 or 127.0.0.1)"
$AgentContent = Get-Content $AgentPath -Raw
$AgentContent = $AgentContent -replace '(?m)^\$CentralServerIP\s*=\s*".*"', "`$CentralServerIP = `"$TargetIP`""
Set-Content -Path $AgentPath -Value $AgentContent -NoNewline
Write-Host "[+] Agent script successfully updated with target routing: $TargetIP" -ForegroundColor Green
Write-Host ""

# 2. Configure SSL/TLS Certificate Architecture
Write-Host "[*] Step 2: SSL/TLS Certificate Integration" -ForegroundColor Yellow
Write-Host "Select the PKI architecture for the HTTPS listener:"
Write-Host "  [1] Auto-Generate an Ephemeral Self-Signed Certificate (Default)"
Write-Host "  [2] Bind an Existing Enterprise Certificate (Requires Thumbprint)"
$CertChoice = Read-Host "Select Option (1 or 2)"

$ListenerContent = Get-Content $ListenerPath -Raw

if ($CertChoice -eq '2') {
    $Thumbprint = Read-Host "Enter the exact SHA-1 Thumbprint of the Enterprise Certificate"
    $ListenerContent = $ListenerContent -replace '(?m)^\$TargetThumbprint\s*=\s*".*"', "`$TargetThumbprint = `"$Thumbprint`""
    Write-Host "[+] Server configured to enforce Enterprise Certificate: $Thumbprint" -ForegroundColor Green
} else {
    $ListenerContent = $ListenerContent -replace '(?m)^\$TargetThumbprint\s*=\s*".*"', "`$TargetThumbprint = `"AUTO`""
    Write-Host "[+] Server configured for Self-Signed Ephemeral generation." -ForegroundColor Green
}
Write-Host ""

# 3. Configure External Threat Intelligence (Zero-Trust Storage)
Write-Host "[*] Step 3: Threat Intelligence API Integration" -ForegroundColor Yellow
Write-Host "Select the external heuristic engine for automated triage:"
Write-Host "  [1] VirusTotal (Free Tier - Strict 15s Rate Limit)"
Write-Host "  [2] VirusTotal (Paid Enterprise Tier - No Rate Limit)"
Write-Host "  [3] AlienVault OTX (Free - High Volume)"
Write-Host "  [4] Custom MISP Instance"
Write-Host "  [5] Custom Proprietary API"
Write-Host "  [6] DISABLED (Local Zero-Trust Heuristics Only)"
$IntelChoice = Read-Host "Select Option (1-6)"

$IntelMode = "DISABLED"
switch ($IntelChoice) {
    '1' { $IntelMode = "VT-FREE" }
    '2' { $IntelMode = "VT-PAID" }
    '3' { $IntelMode = "OTX" }
    '4' { $IntelMode = "MISP" }
    '5' { $IntelMode = "CUSTOM" }
}

if ($IntelMode -ne "DISABLED") {
    $TargetUrl = ""
    if ($IntelMode -in "MISP", "CUSTOM") {
        Write-Host "(!) For MISP/CUSTOM routing, provide the target URL construct." -ForegroundColor DarkGray
        if ($IntelMode -eq "CUSTOM") { Write-Host "    Use '{HASH}' as the placeholder. E.g., https://api.myintel.com/v1/hash/{HASH}" -ForegroundColor DarkGray }
        if ($IntelMode -eq "MISP") { Write-Host "    E.g., https://misp.yourdomain.local" -ForegroundColor DarkGray }
        $TargetUrl = Read-Host "Enter Target URL"
    }

    # DPAPI Secret Vault Implementation (Hardened against paste-truncation)
    $ConfigDir = "C:\SolenyaEngine\Config"
    if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir | Out-Null }

    $RawKey = Read-Host "Enter your API Key (Bearer Token)"
    $CleanKey = $RawKey.Trim() # Mathematically strips invisible carriage returns
    
    $SecureKey = ConvertTo-SecureString $CleanKey -AsPlainText -Force
    $SecureKey | ConvertFrom-SecureString | Set-Content "$ConfigDir\intel_api.sec" -Force
    
    $ListenerContent = $ListenerContent -replace '(?m)^\$ThreatIntelMode\s*=\s*".*"', "`$ThreatIntelMode = `"$IntelMode`""
    $ListenerContent = $ListenerContent -replace '(?m)^\$ThreatTargetUrl\s*=\s*".*"', "`$ThreatTargetUrl = `"$TargetUrl`""
    
    Write-Host "[+] Threat Intelligence Engine securely armed for: $IntelMode" -ForegroundColor Green
} else {
    $ListenerContent = $ListenerContent -replace '(?m)^\$ThreatIntelMode\s*=\s*".*"', "`$ThreatIntelMode = `"DISABLED`""
    Write-Host "[+] External Threat Intelligence disabled. Relying strictly on local zero-trust heuristics." -ForegroundColor Green
}

# Finalize configuration write to Listener.ps1
Set-Content -Path $ListenerPath -Value $ListenerContent -NoNewline

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "[SUCCESS] Setup Complete. The engine is configured and secured." -ForegroundColor Green
Write-Host "Next Step: Execute .\Listener.ps1 to initialize the Command Center." -ForegroundColor Yellow
Write-Host "=====================================================" -ForegroundColor Cyan