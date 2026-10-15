# Atomic test - rule 4aae4b03-4807-428a-ac89-5c5f3cda65e4
#   "Reconnaissance Command Burst (Hunting)"  (process_creation)
#
# Runs the read-only discovery commands the rule keys on. whoami and net only
# print local information; nltest is skipped so nothing queries a domain.
$ErrorActionPreference = 'SilentlyContinue'
& whoami.exe /priv | Out-Null
& cmd.exe /c 'net localgroup administrators' | Out-Null
exit 0
