# Atomic test for the three process events sharing one ParentImage.
# A uniquely named parent keeps this test's events in their own group. Each
# child is a copy of cmd.exe and echoes text after a short loopback ping.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP ('rustinel-recovery-atomic-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $dir | Out-Null
try {
    foreach ($name in @('atomic-parent.exe', 'vssadmin.exe', 'bcdedit.exe', 'sc.exe')) {
        Copy-Item "$env:SystemRoot\System32\cmd.exe" (Join-Path $dir $name)
    }
    $batch = Join-Path $dir 'fixture.cmd'
    @'
@echo off
"%~dp0vssadmin.exe" /d /c "ping -n 2 127.0.0.1 >nul & echo delete shadows" || exit /b 1
"%~dp0bcdedit.exe" /d /c "ping -n 2 127.0.0.1 >nul & echo recoveryenabled off" || exit /b 1
"%~dp0sc.exe" /d /c "ping -n 2 127.0.0.1 >nul & echo stop Sysmon" || exit /b 1
'@ | Set-Content -Encoding Ascii -Path $batch
    $parent = Start-Process -FilePath (Join-Path $dir 'atomic-parent.exe') `
        -WorkingDirectory $dir -ArgumentList '/d', '/c', 'fixture.cmd' -NoNewWindow -Wait -PassThru
    if ($parent.ExitCode -ne 0) { throw 'Recovery correlation fixture failed' }
} finally {
    Remove-Item $dir -Recurse -Force
}
