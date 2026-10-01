# Atomic test - rule 7d2a8f31-4b6c-49e0-a1f8-3c5d9e0b2a05
#   "LSASS Memory Dump via comsvcs.dll MiniDump"  (process_creation)
#
# Calls the comsvcs MiniDump export by ordinal (#24) rather than by name, the
# usual evasion of rules that key on the string MiniDump. The PID is invalid, so
# no LSASS access or real dump is attempted. '#24' is quoted because an
# unquoted # starts a PowerShell comment.
$ErrorActionPreference = 'SilentlyContinue'
$out = Join-Path $PWD 'rustinel_atomic_minidump_ordinal.dmp'
& rundll32.exe C:\Windows\System32\comsvcs.dll, '#24' 0 $out full | Out-Null
Remove-Item $out -Force -ErrorAction SilentlyContinue
exit 0
