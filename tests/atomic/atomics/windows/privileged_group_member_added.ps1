# Atomic test - rule 859d9985-7720-42b1-a557-c1f6f8972642
#   "Member Added to Privileged Group"  (security 4732)
#
# Creates a local test user and adds it to Administrators (4732, group SID
# S-1-5-32-544), then deletes it. Enables "Security Group Management" first,
# by GUID, and restores the audit policy afterwards.
$ErrorActionPreference = 'SilentlyContinue'
$backup = Join-Path $env:TEMP 'rustinel_atomic_auditpol_4732.csv'
$user = 'rustinel_atomic_grpuser'

& auditpol.exe /backup /file:$backup 2>&1 | Out-Null
& auditpol.exe /set /subcategory:'{0CCE9237-69AE-11D9-BED3-505054503030}' /success:enable 2>&1 | Out-Null

$o1 = & net.exe user $user 'P@ssw0rd-Atomic-123!' /add 2>&1; $c1 = $LASTEXITCODE
$sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$admins = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
$o2 = & net.exe localgroup $admins $user /add 2>&1; $c2 = $LASTEXITCODE
Start-Sleep -Seconds 2

& net.exe localgroup $admins $user /delete 2>&1 | Out-Null
& net.exe user $user /delete 2>&1 | Out-Null
if (Test-Path $backup) {
  & auditpol.exe /restore /file:$backup 2>&1 | Out-Null
  Remove-Item $backup -Force
}
# DEBUG-4732
"admins=$admins c1=$c1 c2=$c2"; $o1; $o2
auditpol.exe /get /subcategory:'{0CCE9237-69AE-11D9-BED3-505054503030}','{0CCE9235-69AE-11D9-BED3-505054503030}'
$ErrorActionPreference = 'Continue'
$ev = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4720 or EventID=4732 or EventID=4733 or EventID=4726 or EventID=4722 or EventID=4738)]]" -MaxEvents 8 -ErrorAction Continue 2>&1
$ev | ForEach-Object { if ($_.Id) { "$($_.Id) $($_.TimeCreated.ToString('HH:mm:ss')) " + (($_.Properties | ForEach-Object { $_.Value }) -join '|') } else { "ERR $_" } }
(Get-Date).ToString('HH:mm:ss')
exit 0
