# Install Sysinternals Sysmon with the SwiftOnSecurity config (SPEC §5.1). Idempotent.
$ErrorActionPreference = "Stop"
$cfg = Join-Path $PSScriptRoot "sysmonconfig-export.xml"
$tools = "C:\Tools"
New-Item -ItemType Directory -Force -Path $tools | Out-Null
$sysmon = Join-Path $tools "Sysmon64.exe"
if (-not (Test-Path $sysmon)) {
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
        -OutFile "$tools\Sysmon.zip"
    Expand-Archive "$tools\Sysmon.zip" -DestinationPath $tools -Force
}
$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc) {
    & $sysmon -c $cfg
} else {
    & $sysmon -accepteula -i $cfg
}
Write-Host "Sysmon installed/updated with $cfg"

# Enable PowerShell Script Block + Module logging and Security process-creation auditing so the
# telemetry matches the Sigma pack's logsources.
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
# Capture full command line in 4688 events
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
