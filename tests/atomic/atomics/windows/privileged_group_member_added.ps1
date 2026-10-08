# Atomic test - rule 859d9985-7720-42b1-a557-c1f6f8972642
#   "Member Added to Privileged Group"  (security 4732)
#
# Creates a local test user and adds it to Administrators (4732, group SID
# S-1-5-32-544), then deletes it. Enables "Security Group Management" first,
# by GUID, and restores the audit policy afterwards.
$ErrorActionPreference = 'SilentlyContinue'
$backup = Join-Path $env:TEMP 'rustinel_atomic_auditpol_4732.csv'
$user = 'rustinel_atomic_grpuser'

& auditpol.exe /backup /file:$backup | Out-Null
& auditpol.exe /set /subcategory:'{0CCE9237-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null

& net.exe user $user 'P@ssw0rd-Atomic-123!' /add | Out-Null
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
# DEBUG-4732
'admins=' + $admins
auditpol.exe /get /subcategory:'{0CCE9237-69AE-11D9-BED3-505054503030}','{0CCE9235-69AE-11D9-BED3-505054503030}'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4728,4732,4733,4726} -MaxEvents 6 | ForEach-Object { "$($_.Id) $($_.TimeCreated) $(($_.Properties | ForEach-Object { $_.Value }) -join '|')" }
exit 0
