# Atomic test - rule 35866351-9855-465f-9927-d10eef7c8aea
#   "AMSI Provider Registration Removed"  (registry_delete)
#
# Registers a fake provider GUID under HKLM\SOFTWARE\Microsoft\AMSI\Providers
# and deletes it again. No AMSI provider DLL exists behind the GUID, so scanning
# is unaffected; the rule keys on the delete.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{7a1e5c20-0000-4e00-8000-5275737469a1}'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'Name' -Value 'rustinel-atomic' -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item -Path $key -Recurse -Force
Start-Sleep -Seconds 1
exit 0
