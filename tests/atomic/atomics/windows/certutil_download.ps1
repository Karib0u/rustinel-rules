# Atomic test - rule 3e2d1c0b-5a4f-4938-8271-6a5b4c3d2e10
#   "Certutil Used to Download Remote Content (Hunting)"  (process_creation)
#
# Runs certutil with the urlcache + -split download flags the rule keys on,
# pointed at a closed local port so nothing is fetched. The detection fires on
# the certutil command line, not on a successful download.
$ErrorActionPreference = 'SilentlyContinue'
$out = Join-Path $PWD 'rustinel_atomic_certutil.tmp'
& certutil.exe -urlcache -split -f "http://127.0.0.1:9/payload" $out | Out-Null
Remove-Item $out -Force -ErrorAction SilentlyContinue
exit 0
