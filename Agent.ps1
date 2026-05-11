<#
.SYNOPSIS
    Solenya Integrity Engine - Endpoint Integrity Agent
.DESCRIPTION
    Executes on Event ID 4657. Interrogates persistence mechanisms, validates signatures, 
    performs native byte-sequence heuristic scanning, maps to MITRE ATT&CK, 
    secures local state via DPAPI, and transmits cryptographically secured deltas.
#>

$CentralServerIP = "127.0.0.1" 
$EndpointUri = "https://$CentralServerIP/telemetry"
$StateCachePath = "C:\ProgramData\SolenyaEngine\state.b64"

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security

$Hostname = $env:COMPUTERNAME
$CurrentState = @{}
$TelemetryPayload = @()

# 1. Initialize Local State Repository
$StateDir = Split-Path $StateCachePath
if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir | Out-Null }

# 2. Load Local Baseline (DPAPI Decryption)
$PreviousState = @{}
if (Test-Path $StateCachePath) {
    try {
        $EncryptedBytes = [Convert]::FromBase64String((Get-Content $StateCachePath -Raw))
        $DecryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($EncryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $LoadedData = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes) | ConvertFrom-Json
        foreach ($Item in $LoadedData) { $PreviousState[$Item.TargetName] = $Item.StateHash }
    } catch { Write-Warning "[-] DPAPI Decryption Failed. Rebuilding analytical baseline..." }
}

# 3. Interrogate Operating System State (Persistence Vectors)
$Targets = @()

# 3a. Services (T1543.003)
$Services = Get-CimInstance Win32_Service -Filter "StartMode = 'Auto' OR State = 'Running'"
foreach ($Service in $Services) {
    $RawPath = $Service.PathName
    if ([string]::IsNullOrWhiteSpace($RawPath)) { continue }
    $CleanPath = ($RawPath -replace '"', '' -split ' \-', 2)[0] -split ' /', 2 | Select-Object -First 1
    $Arguments = $RawPath.Replace($CleanPath.Trim(), "").Replace('"',"").Trim()
    $Targets += [PSCustomObject]@{ TargetName = "SVC: $($Service.Name)"; Path = $CleanPath.Trim(); Args = $Arguments; MITRE = "T1543.003" }
}

# 3b. Run Keys (T1547.001)
$RunKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RunKeys = Get-ItemProperty -Path $RunKeyPath -ErrorAction SilentlyContinue
if ($null -ne $RunKeys) {
    foreach ($Property in $RunKeys.psobject.properties) {
        if ($Property.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
            $RawPath = ($Property.Value -replace '"', '' -split ' \-', 2)[0]
            $Arguments = $Property.Value.Replace($RawPath.Trim(), "").Replace('"',"").Trim()
            $Targets += [PSCustomObject]@{ TargetName = "RUN: $($Property.Name)"; Path = $RawPath.Trim(); Args = $Arguments; MITRE = "T1547.001" }
        }
    }
}

# 3c. WMI Event Subscriptions (T1546.003)
$WmiConsumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
foreach ($Consumer in $WmiConsumers) {
    $Targets += [PSCustomObject]@{ TargetName = "WMI: $($Consumer.Name)"; Path = "WMI_IN_MEMORY"; Args = $Consumer.CommandLineTemplate; MITRE = "T1546.003" }
}

# 3d. COM Hijacking (T1546.015)
$ComHive = "HKCU:\Software\Classes\CLSID"
if (Test-Path $ComHive) {
    $ComKeys = Get-ChildItem -Path $ComHive -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "InprocServer32" }
    foreach ($Key in $ComKeys) {
        $DllPath = (Get-ItemProperty -Path $Key.PSPath -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
        if ($null -ne $DllPath) {
            $Clsid = $Key.PSParentPath -split '::' | Select-Object -Last 1 | Split-Path -Leaf
            $Targets += [PSCustomObject]@{ TargetName = "COM: $Clsid"; Path = $DllPath.Trim(); Args = ""; MITRE = "T1546.015" }
        }
    }
}

# 4. Delta Detection & Native Byte-Sequence Heuristics
foreach ($Target in $Targets) {
    $Hash = "FILE_NOT_FOUND"
    $SigStatus = "NotApplicable"
    $Signer = "N/A"
    $ByteHeuristics = "Nominal"

    if ($Target.Path -eq "WMI_IN_MEMORY") {
        $Hash = [System.BitConverter]::ToString((New-Object Security.Cryptography.SHA256Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes($Target.Args))).Replace("-", "")
    } elseif (Test-Path $Target.Path -PathType Leaf) {
        $Hash = (Get-FileHash -Path $Target.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $Sig = Get-AuthenticodeSignature -FilePath $Target.Path -ErrorAction SilentlyContinue
        $SigStatus = if ($null -ne $Sig) { $Sig.Status.ToString() } else { "NotSigned" }
        $Signer = if ($Sig.Status -eq 'Valid') { $Sig.SignerCertificate.Subject } else { "N/A" }
        
        try {
            $Bytes = Get-Content -Path $Target.Path -Encoding Byte -TotalCount 4096 -ErrorAction SilentlyContinue
            $StringData = [System.Text.Encoding]::ASCII.GetString($Bytes)
            if ($StringData -match "(VirtualAlloc|WriteProcessMemory|ReflectiveLoader|Invoke-)") {
                $ByteHeuristics = "ANOMALOUS_BYTE_SEQUENCE"
            }
        } catch {}
    }
    
    # Cryptographic Execution State Binding (Prevents Argument Hijacking)
    $ExecutionState = "$Hash|$($Target.Args)"
    $CurrentState[$Target.TargetName] = $ExecutionState
    
    # Delta Check
    if (-not $PreviousState.ContainsKey($Target.TargetName) -or $PreviousState[$Target.TargetName] -ne $ExecutionState) {
        $BehavioralFlag = $ByteHeuristics
        if ($Target.Args -match "(?i)(-enc|-encodedcommand|FromBase64String|http|IEX|Invoke-Expression|-w hidden|-WindowStyle Hidden)") {
            $BehavioralFlag = "ANOMALOUS_ARGUMENTS"
        }

        $TelemetryPayload += [PSCustomObject]@{
            Hostname    = $Hostname
            Timestamp   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            ServiceName = $Target.TargetName
            ProcessId   = 0 
            Path        = $Target.Path
            Arguments   = $Target.Args
            SHA256      = $Hash       
            Signature   = $SigStatus
            Signer      = $Signer
            Behavior    = $BehavioralFlag
            MITRE       = $Target.MITRE
            State       = if ($PreviousState.ContainsKey($Target.TargetName)) { "MODIFIED" } else { "NEW" }
        }
    }
}

# 4.5 Merge Long-Term Memory (Prevents Transient Service Amnesia)
foreach ($Key in $PreviousState.Keys) {
    if (-not $CurrentState.ContainsKey($Key)) {
        $CurrentState[$Key] = $PreviousState[$Key]
    }
}

# 5. Secure Local Memory (DPAPI State Update)
if ($TelemetryPayload.Count -gt 0) {
    $JsonPayload = $TelemetryPayload | ConvertTo-Json -Depth 3 -Compress
    
    try {
        $CurrentStateObjects = $CurrentState.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{ TargetName = $_.Key; StateHash = $_.Value }
        }
        $StateJson = $CurrentStateObjects | ConvertTo-Json -Depth 2 -Compress
        $StateBytes = [System.Text.Encoding]::UTF8.GetBytes($StateJson)
        $EncryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($StateBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        
        [Convert]::ToBase64String($EncryptedBytes) | Set-Content -Path $StateCachePath -Force
    } catch { }

# 6. Telemetry Dispatch
    try {
        Invoke-RestMethod -Uri $EndpointUri -Method Post -Body $JsonPayload -ContentType "application/json" -TimeoutSec 5 | Out-Null
    } catch { }
}