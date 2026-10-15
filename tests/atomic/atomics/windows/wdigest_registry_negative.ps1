# Negative fixture for rule b4d8f0c5-3a92-4e67-9d1b-7c3e2f5a0d23
# Writes the secure default (UseLogonCredential = 0) under the same HKCU-only
# key. The rule must not alert on it.
$ErrorActionPreference = 'SilentlyContinue'
$root = 'HKCU:\Control'
$key = "$root\SecurityProviders\WDigest"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'UseLogonCredential' -Value 0 -PropertyType DWord -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
exit 0
