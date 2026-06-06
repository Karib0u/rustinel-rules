# Atomic test - rule 5e8b1d44-9c2a-4f67-8d03-7b1a6e3c9d08
#   "Windows Event Log Cleared via Command Line"  (process_creation)
#
# Invokes wevtutil cl against a test log name. Success is not required because
# the process command line is the detection source.
$ErrorActionPreference = 'SilentlyContinue'
& wevtutil.exe cl RustinelAtomicLog | Out-Null
exit 0
