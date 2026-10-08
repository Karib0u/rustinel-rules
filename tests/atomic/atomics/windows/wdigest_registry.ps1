# Atomic test - rule b4d8f0c5-3a92-4e67-9d1b-7c3e2f5a0d23
#   "WDigest Cleartext Credential Caching Enabled"  (registry_set)
#
# Sets a UseLogonCredential DWORD of 1 under an HKCU-only WDigest-shaped key
# (the live HKLM setting is never touched), then removes the whole key tree.
$ErrorActionPreference = 'SilentlyContinue'
$root = 'HKCU:\Control'
$key = "$root\SecurityProviders\WDigest"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'UseLogonCredential' -Value 1 -PropertyType DWord -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
exit 0
