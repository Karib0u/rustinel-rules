# Atomic test - rule e06d7901-46b7-4fe9-a7cb-bbcab05ac0b1
#   "Microsoft Defender Real-Time Protection Disabled"  (windefend 5001)
#
# Turns real-time monitoring off for a few seconds and back on. Tamper
# Protection can block the change on some images; the manifest marks this test
# allow_failure until a run proves it. Re-enabled in `finally`.
$ErrorActionPreference = 'SilentlyContinue'
try {
  Set-MpPreference -DisableRealtimeMonitoring $true
  Start-Sleep -Seconds 3
} finally {
  Set-MpPreference -DisableRealtimeMonitoring $false
}
exit 0
