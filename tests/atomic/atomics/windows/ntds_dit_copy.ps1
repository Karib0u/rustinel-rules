# Atomic test - rule 6228b718-bcc1-4901-80b9-e2a6fc23a4a6
#   "NTDS.dit Copied or Accessed with a File Tool"  (process_creation)
#
# Runs cmd.exe copy against a non-existent ntds.dit path. The copy fails
# harmlessly; the process command line is the detection source.
$ErrorActionPreference = 'SilentlyContinue'
$src = Join-Path $env:TEMP 'rustinel-ntds-missing\ntds.dit'
$dst = Join-Path $env:TEMP 'rustinel-ntds-copy.dit'
& cmd.exe /c copy $src $dst | Out-Null
Remove-Item $dst -Force -ErrorAction SilentlyContinue
exit 0
