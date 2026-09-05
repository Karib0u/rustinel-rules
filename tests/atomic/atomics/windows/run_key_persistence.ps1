# Atomic test - rule a1b2c3d4-7e8f-4012-9a3b-4c5d6e7f0a10
# Creates a harmless HKCU autorun value, verifies the write, then removes it.
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$name = 'RustinelAtomicTest'

# Fresh runner profiles may not have a Run key. Do not overwrite an existing key.
if (-not (Test-Path -LiteralPath $key)) {
    New-Item -Path $key -Force | Out-Null
}

try {
    New-ItemProperty -LiteralPath $key -Name $name -Value 'notepad.exe' -PropertyType String -Force | Out-Null
    $value = Get-ItemPropertyValue -LiteralPath $key -Name $name
    if ($value -ne 'notepad.exe') {
        throw "Run key write verification failed: expected notepad.exe, got '$value'"
    }
    Start-Sleep -Seconds 1
} finally {
    Remove-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue
}
