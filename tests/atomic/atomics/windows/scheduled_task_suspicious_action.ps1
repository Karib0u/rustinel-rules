# Atomic test - rule 3a1cdc64-a2a1-444b-a04b-32a3f1d09a99
#   "Scheduled Task Registered With Suspicious Action"  (security 4698)
#
# Security 4698 is written only when the "Other Object Access Events" audit
# subcategory is enabled, which Windows leaves off by default. The script backs
# up the audit policy, enables that subcategory, registers a task whose action is
# cmd.exe with a C:\Users\Public argument, then removes the task and restores the
# policy. The task has no trigger, so it never runs.
$ErrorActionPreference = 'SilentlyContinue'
$backup = Join-Path $env:TEMP 'rustinel_atomic_auditpol.csv'
$name = 'RustinelAtomicSuspiciousTask'

& auditpol.exe /backup /file:$backup | Out-Null
# By GUID, so it also works on non-English Windows.
& auditpol.exe /set /subcategory:'{0CCE9227-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null

$action = New-ScheduledTaskAction -Execute 'cmd.exe' `
  -Argument '/c type C:\Users\Public\rustinel_atomic_task.txt'
Register-ScheduledTask -TaskName $name -Action $action -Force | Out-Null
Start-Sleep -Seconds 2

Unregister-ScheduledTask -TaskName $name -Confirm:$false
if (Test-Path $backup) {
  & auditpol.exe /restore /file:$backup | Out-Null
  Remove-Item $backup -Force
}
exit 0
