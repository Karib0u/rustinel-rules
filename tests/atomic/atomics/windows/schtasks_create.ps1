# Atomic test - rule 4a596825-4674-4db3-b360-842435edf11a
#   "Scheduled Task Creation via Schtasks"  (process_creation)
#
# Creates and deletes a harmless once-only scheduled task.
$ErrorActionPreference = 'SilentlyContinue'
$name = '\RustinelAtomicCreate'
& schtasks.exe /Create /TN $name /SC ONCE /ST 23:59 /TR "cmd.exe /c exit 0" /F | Out-Null
Start-Sleep -Seconds 1
& schtasks.exe /Delete /TN $name /F | Out-Null
exit 0
