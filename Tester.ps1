<#
.SYNOPSIS
    Solenya Integrity Engine - Standard Persistence Emulation
.DESCRIPTION
    Safely triggers the engine's LOLbin (Living off the Land) heuristics 
    by registering calc.exe as a background service.
#>

#Requires -RunAsAdministrator

Write-Host "[*] Emulating Contextual Anomaly: Establishing anomalous persistence via native binary..." -ForegroundColor Yellow

New-Service -Name "SolenyaTest" -BinaryPathName "C:\Windows\System32\calc.exe" -StartupType Automatic | Out-Null

Write-Host "[+] Service created. The analytical engine will contextualize the risk." -ForegroundColor Green
Write-Host "    (Run Scrubber.ps1 to cleanly remove this test service)" -ForegroundColor DarkGray