<#
.SYNOPSIS
    Solenya Integrity Engine - Advanced Fileless Emulation
.DESCRIPTION
    Safely triggers the engine's Behavioral Heuristics by registering a service
    with obfuscated (Base64) execution arguments.
#>

#Requires -RunAsAdministrator

Write-Host "[*] Emulating Behavioral Anomaly: Fileless Execution Sequence..." -ForegroundColor Yellow

# This Base64 string simply translates to: Write-Host 'Solenya Behavioral Test'
$BenignPayload = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBvAGwAZQBuAHkAYQAgAEIAZQBoAGEAdgBpAG8AcgBhAGwAIABUAGUAcwB0ACcA"
$SuspiciousArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $BenignPayload"

New-Service -Name "SolenyaBehavioral" -BinaryPathName "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe $SuspiciousArgs" -StartupType Automatic | Out-Null

Write-Host "[+] Behavioral emulation service established. The heuristic engine will process the arguments." -ForegroundColor Green
Write-Host "    (Run Scrubber.ps1 to cleanly remove this test service)" -ForegroundColor DarkGray