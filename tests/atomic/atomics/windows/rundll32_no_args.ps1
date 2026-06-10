# Atomic test - rule 9c8b7a6e-1d2f-4a3b-9c0d-2e3f4a5b6c71
#   "Rundll32 Execution Without Standard Arguments"  (process_creation)
#
# Starts rundll32.exe without DLL or CPL arguments.
$ErrorActionPreference = 'SilentlyContinue'
& rundll32.exe | Out-Null
exit 0
