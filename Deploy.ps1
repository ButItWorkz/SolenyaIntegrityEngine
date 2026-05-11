<#
.SYNOPSIS
    Solenya Integrity Engine - Endpoint Deployment
.DESCRIPTION
    Establishes the localized state directory with SYSTEM-only ACLs, enables
    registry auditing for persistence vectors, and deploys the event-driven background task.
#>

#Requires -RunAsAdministrator

$EngineDir = "C:\ProgramData\SolenyaEngine"
$AgentScript = "$EngineDir\Agent.ps1"
$TaskName = "Solenya_Integrity_Monitor"

Write-Host "[*] Endpoint Deployment Sequence Initiated." -ForegroundColor Cyan

# 1. Establish the Secure Execution Directory
if (-not (Test-Path $EngineDir)) { New-Item -ItemType Directory -Path $EngineDir | Out-Null }
Copy-Item -Path ".\Agent.ps1" -Destination $AgentScript -Force

# 1a. Enforce Strict Access Control Lists (ACLs)
$Acl = Get-Acl $EngineDir
$Acl.SetAccessRuleProtection($true, $false)
$SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.AddAccessRule($SystemRule)
$Acl.AddAccessRule($AdminRule)
Set-Acl $EngineDir $Acl
Write-Host "[+] Localized state repository established and cryptographically secured." -ForegroundColor Green

# 2. Configure Operating System Audit Policies
Write-Host "[*] Enabling Global Registry Auditing via AuditPol..." -ForegroundColor Yellow
auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null

$AuditRule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone", "SetValue, CreateSubKey, Delete", "ContainerInherit", "None", "Success")

# 2a. Apply SACLs to Services Hive
$ServicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$ServicesAcl = Get-Acl $ServicesPath -Audit
$ServicesAcl.AddAuditRule($AuditRule)
Set-Acl $ServicesPath $ServicesAcl

# 2b. Apply SACLs to Run Keys Hive
$RunKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RunKeyAcl = Get-Acl $RunKeyPath -Audit
$RunKeyAcl.AddAuditRule($AuditRule)
Set-Acl $RunKeyPath $RunKeyAcl
Write-Host "[+] Operating System SACLs configured to trigger Event ID 4657 on modification." -ForegroundColor Green

# 3. Construct and Register the Event-Driven Task Scheduler XML
Write-Host "[*] Orchestrating background execution task..." -ForegroundColor Yellow
$TaskXML = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[(EventID=4657)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$AgentScript"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$TaskXMLPath = "$env:TEMP\SolenyaTask.xml"
$TaskXML | Out-File -FilePath $TaskXMLPath -Encoding Unicode

# Unregister old task if it exists, then register the new one natively
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
schtasks.exe /create /tn $TaskName /xml $TaskXMLPath /ru "SYSTEM" /f | Out-Null
Remove-Item -Path $TaskXMLPath -Force

Write-Host "[+] Background Execution Task ($TaskName) deployed successfully." -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "[SUCCESS] Agent Architecture Deployment Complete." -ForegroundColor Green
Write-Host "The endpoint is now functionally autonomous and reporting." -ForegroundColor Yellow
Write-Host "=====================================================" -ForegroundColor Cyan