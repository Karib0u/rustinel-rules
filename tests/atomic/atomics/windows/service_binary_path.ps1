# Atomic test - rule d4e5f6a7-0123-4345-9d6e-7f8a9b012a13
#   "Suspicious Service Binary Path"  (service_creation)
#
# Registers a demand-start service whose binary is a cmd.exe command line, then
# deletes it. The service is never started.
$ErrorActionPreference = 'SilentlyContinue'
$name = 'RustinelAtomicSvc'
& sc.exe delete $name | Out-Null
& sc.exe create $name binPath= 'cmd.exe /c exit 0' start= demand | Out-Null
Start-Sleep -Seconds 2
& sc.exe delete $name | Out-Null
exit 0
