# Atomic test - rule e7a1b9c2-4d6f-4a83-b2e5-1c0d9f3a4b20
#   "Registry Hive Dump via reg.exe save"  (process_creation)
#
# Saves HKLM\SAM to a temporary file on the disposable runner, then deletes it.
$ErrorActionPreference = 'SilentlyContinue'
$out = Join-Path $PWD 'rustinel_atomic_sam.hiv'
& reg.exe save HKLM\SAM $out /y | Out-Null
Remove-Item $out -Force -ErrorAction SilentlyContinue
exit 0
