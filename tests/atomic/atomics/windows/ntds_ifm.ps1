# Atomic test - rule a3c7e9b4-2f81-4d56-8c0a-6b2d1f4e9c22
#   "Active Directory Database (NTDS.dit) Extraction via ntdsutil IFM"  (process_creation)
#
# Copies cmd.exe to ntdsutil.exe and emits the ntdsutil IFM command-line shape
# (activate instance ntds, ifm, create full). Nothing touches Active Directory.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-ntdsutil-atomic'
$bin = Join-Path $dir 'ntdsutil.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo ac i ntds ifm create full rustinel-ifm-atomic | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
