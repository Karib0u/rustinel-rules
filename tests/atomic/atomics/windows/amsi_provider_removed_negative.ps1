# Negative fixture for rule 35866351-9855-465f-9927-d10eef7c8aea
# Creates and deletes a key outside the AMSI providers path. The rule must not alert.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKLM:\SOFTWARE\RustinelAtomicNegative\{7a1e5c20-0000-4e00-8000-5275737469a2}'
New-Item -Path $key -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item -Path 'HKLM:\SOFTWARE\RustinelAtomicNegative' -Recurse -Force
Start-Sleep -Seconds 1
exit 0
