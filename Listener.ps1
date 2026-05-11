<#
.SYNOPSIS
    Solenya Integrity Engine - Central Telemetry Server
.DESCRIPTION
    A zero-dependency standalone repository. Handles PKI/Self-Signed certs, instantiates 
    an in-memory .NET DataTable, ingests telemetry, and natively hosts the HTML Dashboard.
#>

#Requires -RunAsAdministrator

# --- Configuration Flags (Managed by Setup.ps1) ---
$LocalUiEnabled = $true
$SiemForwardingEnabled = $false
$SiemWebhookUrl = ""
$HtmlFilePath = ".\index.html"
$TargetThumbprint = "AUTO"
$ThreatIntelMode = "DISABLED"
$ThreatApiKey = ""  # Intentionally blank. Decrypted into volatile memory at runtime.
$ThreatTargetUrl = ""
# ----------------------------------------------------------

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$ListenPort = 443
$DataDirectory = "C:\SolenyaEngine\Data"
$XmlDatabasePath = "$DataDirectory\Telemetry.xml"
$AppId = [Guid]::NewGuid().ToString("B")

Write-Host "[*] Initializing Solenya Central Server..." -ForegroundColor Cyan

# 1. Initialize Database Directory
if (-not (Test-Path $DataDirectory)) { New-Item -ItemType Directory -Path $DataDirectory | Out-Null }

# 2. Bind SSL/TLS Certificates
if ($TargetThumbprint -eq "AUTO" -or [string]::IsNullOrWhiteSpace($TargetThumbprint)) {
    $Cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -match "CN=SolenyaListener" }
    if (-not $Cert) {
        Write-Host "[*] Generating ephemeral Self-Signed Certificate..." -ForegroundColor Yellow
        $Cert = New-SelfSignedCertificate -DnsName "SolenyaListener" -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(1)
    }
} else {
    Write-Host "[*] Validating Enterprise Certificate Thumbprint: $TargetThumbprint" -ForegroundColor Yellow
    $Cert = Get-Item -Path "Cert:\LocalMachine\My\$TargetThumbprint" -ErrorAction SilentlyContinue
    if (-not $Cert) {
        Write-Host "[-] FATAL ERROR: Certificate with thumbprint $TargetThumbprint not found." -ForegroundColor Red
        exit
    }
}

$Thumbprint = $Cert.Thumbprint
$PortCheck = netsh http show sslcert ipport=0.0.0.0:$ListenPort | Out-String

if ($PortCheck -notmatch $Thumbprint) {
    Write-Host "[*] Binding Certificate to Port $ListenPort..." -ForegroundColor Yellow
    netsh http delete sslcert ipport=0.0.0.0:$ListenPort 2>&1 | Out-Null 
    $netshArgs = "http add sslcert ipport=0.0.0.0:$ListenPort certhash=$Thumbprint appid=$AppId"
    Start-Process -FilePath "netsh.exe" -ArgumentList $netshArgs -Wait -NoNewWindow
    Write-Host "[+] SSL Binding successful." -ForegroundColor Green
} else {
    Write-Host "[+] Port $ListenPort is already natively bound to the correct certificate." -ForegroundColor Green
}

# 3. Instantiate In-Memory DataTable Architecture
$DataTable = New-Object System.Data.DataTable("SolenyaTelemetry")
$DataTable.Columns.Add("Timestamp") | Out-Null
$DataTable.Columns.Add("Hostname") | Out-Null
$DataTable.Columns.Add("ServiceName") | Out-Null
$DataTable.Columns.Add("Path") | Out-Null
$DataTable.Columns.Add("Arguments") | Out-Null
$DataTable.Columns.Add("SHA256") | Out-Null
$DataTable.Columns.Add("Signature") | Out-Null
$DataTable.Columns.Add("State") | Out-Null
$DataTable.Columns.Add("Behavior") | Out-Null
$DataTable.Columns.Add("MITRE") | Out-Null
$DataTable.Columns.Add("VTScore") | Out-Null

if (Test-Path $XmlDatabasePath) {
    Write-Host "[*] Loading previous state from XML database..." -ForegroundColor Yellow
    $DataTable.ReadXml($XmlDatabasePath) | Out-Null
}

# 4. Stand Up Asynchronous HTTP Listener
$Listener = New-Object System.Net.HttpListener
$Listener.Prefixes.Add("https://+:$ListenPort/")
$Listener.Start()

Write-Host "[+] Solenya Server is LIVE and monitoring on port $ListenPort." -ForegroundColor Green
Write-Host "[!] Press CTRL+C to terminate the server safely." -ForegroundColor DarkGray

# 5. Core Asynchronous Polling Loop
try {
    while ($Listener.IsListening) {
        $AsyncResult = $Listener.BeginGetContext($null, $null)
        while (-not $AsyncResult.IsCompleted) {
            Start-Sleep -Milliseconds 200
        }
        $Context = $Listener.EndGetContext($AsyncResult)
        
        # INNER SAFETY NET: Prevents dropped browser connections from killing the server
        try {
            $Request = $Context.Request
            $Response = $Context.Response
            $Path = $Request.Url.AbsolutePath.ToLower()

            # 5a. ROUTE 1: Ingest Endpoint Telemetry
            if ($Request.HttpMethod -eq "POST" -and $Path -match "/telemetry") {
                $StreamReader = New-Object System.IO.StreamReader($Request.InputStream)
                $RawData = $StreamReader.ReadToEnd()
                $StreamReader.Close()

                $ParsedJson = $RawData | ConvertFrom-Json
                $TelemetryArray = if ($ParsedJson -is [array]) { $ParsedJson } else { @($ParsedJson) }
                
                # BULK INGEST PROTECTION: Skip inline API queries if payload > 5 records
                $IsBulkIngest = ($TelemetryArray.Count -gt 5)

                foreach ($Item in $TelemetryArray) {
                    $Row = $DataTable.NewRow()
                    $Row["Timestamp"] = $Item.Timestamp
                    $Row["Hostname"] = $Item.Hostname
                    $Row["ServiceName"] = $Item.ServiceName
                    $Row["Path"] = $Item.Path
                    $Row["Arguments"] = $Item.Arguments
                    $Row["SHA256"] = $Item.SHA256
                    $Row["Signature"] = $Item.Signature
                    $Row["State"] = $Item.State
                    $Row["Behavior"] = $Item.Behavior
                    $Row["MITRE"] = $Item.MITRE
                    $Row["VTScore"] = "N/A"
                    
                    if ($ThreatIntelMode -in "VT-FREE", "VT-PAID", "OTX", "MISP", "CUSTOM") {
                        if ($Item.State -in "NEW", "MODIFIED" -and -not $IsBulkIngest) {
                            try {
                                # Decrypt API Key strictly for this execution cycle
                                if (Test-Path "C:\SolenyaEngine\Config\intel_api.sec") {
                                    $SecureKey = Get-Content "C:\SolenyaEngine\Config\intel_api.sec" | ConvertTo-SecureString
                                    $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
                                    $ThreatApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Ptr)
                                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)
                                }

                                if ($ThreatIntelMode -match "VT") {
                                    $Headers = @{ "x-apikey" = $ThreatApiKey }
                                    $VTUri = "https://www.virustotal.com/api/v3/files/$($Item.SHA256)"
                                    $VTResponse = Invoke-RestMethod -Uri $VTUri -Method Get -Headers $Headers -ErrorAction Stop
                                    $Malicious = $VTResponse.data.attributes.last_analysis_stats.malicious
                                    $Row["VTScore"] = if ($Malicious -gt 0) { "$Malicious Engines Flagged Malicious" } else { "Clean (0 Flags)" }
                                } elseif ($ThreatIntelMode -eq "OTX") {
                                    $Headers = @{ "X-OTX-API-KEY" = $ThreatApiKey }
                                    $OTXUri = "https://otx.alienvault.com/api/v1/indicators/file/$($Item.SHA256)/general"
                                    $OTXResponse = Invoke-RestMethod -Uri $OTXUri -Method Get -Headers $Headers -ErrorAction Stop
                                    $PulseCount = $OTXResponse.pulse_info.count
                                    $Row["VTScore"] = if ($PulseCount -gt 0) { "$PulseCount OTX Pulses Detected" } else { "Clean (0 Pulses)" }
                                } else {
                                    $TargetUrl = $ThreatTargetUrl.Replace("{HASH}", $Item.SHA256)
                                    $Headers = @{ "Authorization" = "Bearer $ThreatApiKey" }
                                    $CustomResponse = Invoke-RestMethod -Uri $TargetUrl -Method Get -Headers $Headers -ErrorAction Stop
                                    $Row["VTScore"] = "External API Validated"
                                }
                            } catch {
                                if ($_.Exception.Message -match "404" -and $ThreatIntelMode -eq "OTX") {
                                    $Row["VTScore"] = "Clean (Not in OTX)"
                                } else {
                                    $Row["VTScore"] = "API Error: $($_.Exception.Message)"
                                }
                            } finally {
                                $ThreatApiKey = "" # Purge from RAM explicitly
                            }
                        } else {
                            $Row["VTScore"] = "Baseline (Skipped API)"
                        }
                    }

                    $DataTable.Rows.Add($Row)
                }

                Write-Host "[+] Ingested $($TelemetryArray.Count) records from $($TelemetryArray[0].Hostname)." -ForegroundColor Green
                $DataTable.WriteXml($XmlDatabasePath, [System.Data.XmlWriteMode]::WriteSchema)
                
                if ($SiemForwardingEnabled -and $SiemWebhookUrl -ne "") {
                    try { Invoke-RestMethod -Uri $SiemWebhookUrl -Method Post -Body $RawData -ContentType "application/json" -TimeoutSec 5 | Out-Null } catch {}
                }
                
                $AckBuffer = [System.Text.Encoding]::UTF8.GetBytes('{"status":"OK"}')
                $Response.ContentType = "application/json"
                $Response.ContentLength64 = $AckBuffer.Length
                $Response.OutputStream.Write($AckBuffer, 0, $AckBuffer.Length)
                $Response.StatusCode = 200
            }
            
            # 5b. ROUTE 2: Serve HTML Dashboard
            elseif ($Request.HttpMethod -eq "GET" -and $Path -match "/dashboard" -and $LocalUiEnabled) {
                if (Test-Path $HtmlFilePath) {
                    $HtmlContent = Get-Content $HtmlFilePath -Raw
                    $Buffer = [System.Text.Encoding]::UTF8.GetBytes($HtmlContent)
                    $Response.ContentType = "text/html"
                    $Response.ContentLength64 = $Buffer.Length
                    $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
                    $Response.StatusCode = 200
                } else { $Response.StatusCode = 404 }
            }
            
            # 5c. ROUTE 3: API Data Source for Dashboard
            elseif ($Request.HttpMethod -eq "GET" -and $Path -match "/api/data" -and $LocalUiEnabled) {
                $DataArray = @()
                foreach ($Row in $DataTable.Rows) {
                    $DataArray += [PSCustomObject]@{
                        Timestamp   = $Row["Timestamp"]
                        Hostname    = $Row["Hostname"]
                        ServiceName = $Row["ServiceName"]
                        Path        = $Row["Path"]
                        Arguments   = $Row["Arguments"]
                        SHA256      = $Row["SHA256"]
                        Signature   = $Row["Signature"]
                        State       = $Row["State"]
                        Behavior    = $Row["Behavior"]
                        MITRE       = $Row["MITRE"]
                        VTScore     = $Row["VTScore"]
                    }
                }
                $JsonData = if ($DataArray.Count -gt 0) { $DataArray | ConvertTo-Json -Depth 2 } else { "[]" }
                $Buffer = [System.Text.Encoding]::UTF8.GetBytes($JsonData)
                $Response.ContentType = "application/json"
                $Response.ContentLength64 = $Buffer.Length
                $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
                $Response.StatusCode = 200
            }

            # 5d. ROUTE 4: Manual Threat Intel Scan Execution
            elseif ($Request.HttpMethod -eq "POST" -and $Path -match "/api/scan" -and $LocalUiEnabled) {
                $StreamReader = New-Object System.IO.StreamReader($Request.InputStream)
                $RawHash = ($StreamReader.ReadToEnd() | ConvertFrom-Json).Hash
                $StreamReader.Close()

                $ScanResult = "Error: Invalid Config"
                
                if ($ThreatIntelMode -in "VT-FREE", "VT-PAID", "OTX", "MISP", "CUSTOM") {
                    try {
                        # Decrypt API Key strictly for this manual scan
                        if (Test-Path "C:\SolenyaEngine\Config\intel_api.sec") {
                            $SecureKey = Get-Content "C:\SolenyaEngine\Config\intel_api.sec" | ConvertTo-SecureString
                            $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
                            $ThreatApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Ptr)
                            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)
                        }

                        if ($ThreatIntelMode -match "VT") {
                            $Headers = @{ "x-apikey" = $ThreatApiKey }
                            $VTUri = "https://www.virustotal.com/api/v3/files/$RawHash"
                            $VTResponse = Invoke-RestMethod -Uri $VTUri -Method Get -Headers $Headers -ErrorAction Stop
                            $Malicious = $VTResponse.data.attributes.last_analysis_stats.malicious
                            $ScanResult = if ($Malicious -gt 0) { "$Malicious Engines Flagged Malicious" } else { "Clean (0 Flags)" }
                        } elseif ($ThreatIntelMode -eq "OTX") {
                            $Headers = @{ "X-OTX-API-KEY" = $ThreatApiKey }
                            $OTXUri = "https://otx.alienvault.com/api/v1/indicators/file/$RawHash/general"
                            $OTXResponse = Invoke-RestMethod -Uri $OTXUri -Method Get -Headers $Headers -ErrorAction Stop
                            $PulseCount = $OTXResponse.pulse_info.count
                            $ScanResult = if ($PulseCount -gt 0) { "$PulseCount OTX Pulses Detected" } else { "Clean (0 Pulses)" }
                        } elseif ($ThreatIntelMode -in "MISP", "CUSTOM" -and $ThreatTargetUrl -ne "") {
                            $TargetUrl = $ThreatTargetUrl.Replace("{HASH}", $RawHash)
                            $Headers = @{ "Authorization" = "Bearer $ThreatApiKey" }
                            $CustomResponse = Invoke-RestMethod -Uri $TargetUrl -Method Get -Headers $Headers -ErrorAction Stop
                            $ScanResult = "External API Validated"
                        }
                    } catch {
                        if ($_.Exception.Message -match "404") { $ScanResult = "Clean (Not in OTX)" } 
                        else { $ScanResult = "API Error: $($_.Exception.Message)" }
                    } finally {
                        $ThreatApiKey = "" # Purge from RAM explicitly
                    }
                }

                $RowsToUpdate = $DataTable.Select("SHA256 = '$RawHash'")
                foreach ($R in $RowsToUpdate) { $R["VTScore"] = $ScanResult }
                $DataTable.WriteXml($XmlDatabasePath, [System.Data.XmlWriteMode]::WriteSchema)

                # Dynamic Rate Limiting Logic (15s for Free Tiers, 2s for Paid/Enterprise)
                $CooldownMs = if ($ThreatIntelMode -eq "VT-FREE") { 15000 } else { 2000 }
                $ResponsePayload = @{ Result = $ScanResult; Cooldown = $CooldownMs }

                $Buffer = [System.Text.Encoding]::UTF8.GetBytes(($ResponsePayload | ConvertTo-Json))
                $Response.ContentType = "application/json"
                $Response.ContentLength64 = $Buffer.Length
                $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
                $Response.StatusCode = 200
            }
            else { $Response.StatusCode = 404 }
            
        } catch {
            Write-Warning "[-] Ignored dropped client connection or pipeline interrupt."
        } finally {
            try { $Response.Close() } catch {}
        }
    }
} finally {
    $Listener.Stop()
    Write-Host "[-] Server offline." -ForegroundColor Red
}