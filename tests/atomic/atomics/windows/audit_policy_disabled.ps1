# Atomic test - rule 5a2fd413-6826-47af-8b6b-9e069058c807
#   "Windows Audit Policy Success or Failure Auditing Removed"  (security 4719)
#
# Backs up the audit policy, makes sure "Audit Policy Change" is audited so 4719
# is written, enables then disables success auditing on "Other Policy Change
# Events" (a removal, %%8448), then restores the policy.
$ErrorActionPreference = 'SilentlyContinue'
$backup = Join-Path $env:TEMP 'rustinel_atomic_auditpol_4719.csv'

& auditpol.exe /backup /file:$backup | Out-Null
# By GUID, so it also works on non-English Windows.
& auditpol.exe /set /subcategory:'{0CCE922F-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
& auditpol.exe /set /subcategory:'{0CCE9234-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
Start-Sleep -Seconds 1
& auditpol.exe /set /subcategory:'{0CCE9234-69AE-11D9-BED3-505054503030}' /success:disable | Out-Null
Start-Sleep -Seconds 2

if (Test-Path $backup) {
  & auditpol.exe /restore /file:$backup | Out-Null
  Remove-Item $backup -Force
}
exit 0
