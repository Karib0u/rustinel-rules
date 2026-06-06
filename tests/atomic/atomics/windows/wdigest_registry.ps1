# Atomic test - rule b4d8f0c5-3a92-4e67-9d1b-7c3e2f5a0d23
#   "WDigest Cleartext Credential Caching Enabled"  (registry_event)
#
# Writes and removes a WDigest key whose path includes the watched value name.
# Registry telemetry exposes the key path but not the value name.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\Control\SecurityProviders\WDigest\UseLogonCredential'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'AtomicValue' -Value 1 -PropertyType DWord -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'HKCU:\Control\SecurityProviders\WDigest' -Force -ErrorAction SilentlyContinue
Remove-Item 'HKCU:\Control\SecurityProviders' -Force -ErrorAction SilentlyContinue
Remove-Item 'HKCU:\Control' -Force -ErrorAction SilentlyContinue
exit 0
