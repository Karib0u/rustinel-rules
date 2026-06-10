# Atomic test - rule 7f3a1c2e-4b5d-4e6f-8a90-1b2c3d4e5f60
#   "Suspicious Encoded PowerShell Command Line"  (process_creation)
#
# Launches powershell.exe with -EncodedCommand, the exact flag the rule keys on.
# The encoded payload is a benign Write-Host, so it just prints a line and exits.
$ErrorActionPreference = 'SilentlyContinue'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host rustinel-atomic-encoded'))
& powershell.exe -NoProfile -EncodedCommand $enc | Out-Null
exit 0
