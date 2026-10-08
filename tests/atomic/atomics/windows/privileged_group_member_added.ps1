# Atomic test - rule 859d9985-7720-42b1-a557-c1f6f8972642
#   "Member Added to Privileged Group"  (security 4732)
#
# Creates a local test user (name <= 20 chars, the net user limit) and adds it to Administrators (4732, group SID
# S-1-5-32-544), then deletes it. Enables "Security Group Management" first,
# by GUID, and restores the audit policy afterwards.
$ErrorActionPreference = 'SilentlyContinue'
$backup = Join-Path $env:TEMP 'rustinel_atomic_auditpol_4732.csv'
$user = 'rustinel_atomic_grp'

& auditpol.exe /backup /file:$backup | Out-Null
& auditpol.exe /set /subcategory:'{0CCE9237-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null

$o1 = (& net.exe user $user 'P@ssw0rd-Atomic-123!' /add 2>&1 | Out-String); $c1 = $LASTEXITCODE
$sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$admins = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
$o2 = (& net.exe localgroup $admins $user /add 2>&1 | Out-String); $c2 = $LASTEXITCODE
Start-Sleep -Seconds 2

& net.exe localgroup $admins $user /delete | Out-Null
& net.exe user $user /delete | Out-Null
if (Test-Path $backup) {
  & auditpol.exe /restore /file:$backup | Out-Null
  Remove-Item $backup -Force
}
"DEBUG c1=$c1 c2=$c2"; $o1; $o2
exit 0
