# Atomic test - rule 7d2a8f31-4b6c-49e0-a1f8-3c5d9e0b2a05
#   "LSASS Memory Dump via comsvcs.dll MiniDump"  (process_creation)
#
# Emits the comsvcs MiniDump command-line tokens with an invalid PID, so no
# LSASS access or real dump is attempted.
$ErrorActionPreference = 'SilentlyContinue'
$out = Join-Path $PWD 'rustinel_atomic_minidump.dmp'
& rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 0 $out full | Out-Null
Remove-Item $out -Force -ErrorAction SilentlyContinue
exit 0
