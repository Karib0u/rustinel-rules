# Atomic test - rule 68d288c3-75fa-4773-b195-684657984534 (process_creation).
# The fixture receives a path without creating or interpreting a script.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{ 'wscript.exe' = "//nologo ""$env:USERPROFILE\Downloads\Rustinel Atomic.js""" }
