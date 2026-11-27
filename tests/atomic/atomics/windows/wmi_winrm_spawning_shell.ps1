# Atomic test - rule aff3a851-eda8-49fa-8e1e-f353a909541e (process_creation).
# Both images are fixture copies. No WMI provider or remote connection is used.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{ 'cmd.exe' = '/c rem RustinelAtomic' } -ParentName 'WmiPrvSE.exe'
