# Atomic test - rule e41b0197-ceee-40dc-92e4-4fd2f25ad59e (image_load).
# The managed command-line fixture loads the real .NET Framework runtime.
# Running the fixture under a script host's basename exercises the ETW image match.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{
    'cscript.exe' = '--rustinel-atomic'
}
