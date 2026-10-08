# Atomic test - rule e813d6f6-5dbb-4587-a60e-20a04481fdc6
#   "Security Event Log Cleared"  (security 1102)
#
# Clears the Security log of the disposable runner. Event 1102 is written
# regardless of audit policy.
$ErrorActionPreference = 'SilentlyContinue'
& wevtutil.exe cl Security | Out-Null
Start-Sleep -Seconds 2
exit 0
