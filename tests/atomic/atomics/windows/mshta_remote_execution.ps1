# Atomic test - rule 3c6f9b22-7e1a-4d85-9c0b-2a8d4e6f1b07
#   "Mshta Remote or Inline Script Execution"  (process_creation)
#
# Starts mshta with an inline script URL. The process exits immediately.
$ErrorActionPreference = 'SilentlyContinue'
& mshta.exe "javascript:close()" | Out-Null
exit 0
