# Atomic test - rule 31ddbaff-1a32-4eb6-b7ce-647b59aeb901
#   "AMSI Bypass Pattern in PowerShell ScriptBlock"  (ps_script)
#
# ScriptBlock logging is off by default. The script saves the policy value,
# enables it, runs the content in a fresh powershell.exe (the policy is read at
# process start), then restores the prior state. The content sits in a branch
# that never executes: the rule matches the logged script text, so nothing is
# downloaded and AMSI is never touched.
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$keyExisted = Test-Path -LiteralPath $key
$prior = $null
if ($keyExisted) {
    $prior = (Get-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
}
$dir = Join-Path $env:TEMP 'rustinel-psscript-atomic'
$file = Join-Path $dir 'amsi_probe.ps1'
try {
    if (-not $keyExisted) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -Value 1 -Type DWord
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Set-Content -LiteralPath $file -Value @'
if ($false) {
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
}
Write-Output 'rustinel-atomic'
'@
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file | Out-Null
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
exit 0
