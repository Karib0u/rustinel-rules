# Atomic test - rule 021a78f0-210b-4932-bb12-26820eedc3c1
#   "Microsoft Defender Exclusion or Disable via PowerShell Command Line"  (process_creation)
#
# Runs PowerShell with an Add-MpPreference exclusion in the command line, only
# printing it; no Defender setting is changed.
$ErrorActionPreference = 'SilentlyContinue'
powershell.exe -NoProfile -Command "Write-Output 'Add-MpPreference -ExclusionPath C:\rustinel-atomic'" | Out-Null
exit 0
