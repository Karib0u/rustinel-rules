# Atomic test - rule a3c7e9b4-2f81-4d56-8c0a-6b2d1f4e9c22
#   "Active Directory Database (NTDS.dit) Extraction"  (process_creation)
#
# Emits a benign command line containing ntds.dit without requiring a domain
# controller or touching an AD database.
$ErrorActionPreference = 'SilentlyContinue'
& cmd.exe /c echo ntds.dit | Out-Null
exit 0
