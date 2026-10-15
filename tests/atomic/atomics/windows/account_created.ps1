# Atomic test - rules 3feb077a-6922-4052-93b8-7b95156ca1e5 ("User Account Created",
# security 4720) and the temporal correlation "Account Created and Added to
# Privileged Group".
#
# Enables "User Account Management" and "Security Group Management" by GUID,
# creates a local test user and adds it to Administrators in the same session
# (same SubjectLogonId), then removes both and restores the audit policy.
$ErrorActionPreference = 'SilentlyContinue'
$backup = Join-Path $env:TEMP 'rustinel_atomic_auditpol_4720.csv'
$user = 'rustinel_atomic_cor'

& auditpol.exe /backup /file:$backup | Out-Null
& auditpol.exe /set /subcategory:'{0CCE9235-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
& auditpol.exe /set /subcategory:'{0CCE9237-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null

& net.exe user $user 'P@ss-Atom1c-9x' /add | Out-Null
$sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$admins = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
& net.exe localgroup $admins $user /add | Out-Null
Start-Sleep -Seconds 2

& net.exe localgroup $admins $user /delete | Out-Null
& net.exe user $user /delete | Out-Null
if (Test-Path $backup) {
  & auditpol.exe /restore /file:$backup | Out-Null
  Remove-Item $backup -Force
}
exit 0
