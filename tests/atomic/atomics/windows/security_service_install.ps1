# Atomic test - rule 2095766d-dd72-41f2-b315-3438406c009a
#   "Service Installed With Suspicious Binary Path (Security 4697)"  (security 4697)
#
# Security 4697 needs the "Security System Extension" audit subcategory, which
# Windows leaves off by default. The script enables it, installs a stopped
# service whose binary path is cmd.exe with a C:\Users\Public argument, then
# deletes the service and restores the policy. The service is never started.
$ErrorActionPreference = 'SilentlyContinue'
$backup = Join-Path $env:TEMP 'rustinel_atomic_auditpol_4697.csv'
$name = 'RustinelAtomicSecSvc'

& auditpol.exe /backup /file:$backup | Out-Null
& auditpol.exe /set /subcategory:'{0CCE9211-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null

& sc.exe create $name binPath= 'cmd.exe /c type C:\Users\Public\rustinel_atomic_svc.txt' start= demand | Out-Null
Start-Sleep -Seconds 2

& sc.exe delete $name | Out-Null
if (Test-Path $backup) {
  & auditpol.exe /restore /file:$backup | Out-Null
  Remove-Item $backup -Force
}
exit 0
