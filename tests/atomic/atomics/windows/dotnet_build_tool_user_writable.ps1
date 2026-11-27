# Atomic test - rule 386d44a5-be07-4868-b53e-3af359b0fb18 (process_creation).
# The fixture never reads or builds a project.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{ 'MSBuild.exe' = '"C:\ProgramData\Rustinel Atomic\fixture.proj"' }
