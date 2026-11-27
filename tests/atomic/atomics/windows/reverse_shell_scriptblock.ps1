# Atomic test - rule ca63dcb9-6578-41fa-be10-e73f1111f2ff (ps_script).
# Logs a fresh script block containing a few inert text markers and a no-op.
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$keyExisted = Test-Path -LiteralPath $key
$prior = $null
if ($keyExisted) {
    $prior = (Get-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
}
$dir = Join-Path $env:TEMP "rustinel-psscript-$([Guid]::NewGuid().ToString('N'))"
$file = Join-Path $dir 'socket_stream_probe.ps1'
try {
    if (-not $keyExisted) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -Value 1 -Type DWord
    New-Item -ItemType Directory -Path $dir | Out-Null
    $probe = @'
<#
SOCKET_TYPE
GetStream(
Invoke-Expression $placeholder
#>
Write-Output 'rustinel atomic test'
'@
    # Keep the full pattern in the child script if logging was already enabled.
    Set-Content -LiteralPath $file -Value $probe.Replace('SOCKET_TYPE', ('System.Net.Sockets.' + 'TcpClient'))
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $file | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Script-block fixture failed' }
    Start-Sleep -Seconds 3
} finally {
    if (-not $keyExisted) {
        Remove-Item -LiteralPath $key -Force -ErrorAction SilentlyContinue
    } elseif ($null -eq $prior) {
        Remove-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
    } else {
        Set-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -Value $prior -Type DWord
    }
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
