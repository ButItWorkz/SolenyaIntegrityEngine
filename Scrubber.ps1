<#
.SYNOPSIS
    Solenya Integrity Engine - Teardown Utility
.DESCRIPTION
    Reverts all architectural modifications made by the deployment sequence.
    Forcefully eradicates test emulation services.
#>

#Requires -RunAsAdministrator

Write-Host "[*] Initiating Solenya Teardown Sequence..." -ForegroundColor Cyan

# 1. Unregister Scheduled Tasks
Unregister-ScheduledTask -TaskName "Solenya_Integrity_Monitor" -Confirm:$false -ErrorAction SilentlyContinue

# 2. Remove Execution Directory
$EngineDir = "C:\ProgramData\SolenyaEngine"
if (Test-Path $EngineDir) {
    Remove-Item -Path $EngineDir -Recurse -Force
}

# 3. Revert Registry Auditing
$AuditRule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone", "SetValue, CreateSubKey, Delete", "ContainerInherit", "None", "Success")

$ServicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$ServicesAcl = Get-Acl $ServicesPath -Audit
$ServicesAcl.RemoveAuditRuleAll($AuditRule)
Set-Acl $ServicesPath $ServicesAcl

$RunKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RunKeyAcl = Get-Acl $RunKeyPath -Audit
$RunKeyAcl.RemoveAuditRuleAll($AuditRule)
Set-Acl $RunKeyPath $RunKeyAcl

auditpol /set /subcategory:"Registry" /success:disable /failure:disable | Out-Null

# 4. Nuclear Eradication of Test/Emulation Services
$TestServices = @("SolenyaTest", "SolenyaBehavioral")

foreach ($Svc in $TestServices) {
    $Service = Get-Service -Name $Svc -ErrorAction SilentlyContinue
    if ($Service) {
        if ($Service.Status -ne 'Stopped') { 
            Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue 
        }
        # WMI Deletion (Bypasses sc.exe "Marked for Deletion" ghosts)
        $WmiSvc = Get-WmiObject -Class Win32_Service -Filter "Name='$Svc'"
        if ($WmiSvc) { $WmiSvc.Delete() | Out-Null }
    }
    # Rip the orphaned keys directly out of the registry as a fallback
    Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Svc" -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[+] Teardown Complete. Endpoint reverted to original state." -ForegroundColor Green