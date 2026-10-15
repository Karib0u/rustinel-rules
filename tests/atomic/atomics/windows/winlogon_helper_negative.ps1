# Negative fixture for rule 52b94494-756b-40d7-af01-8d0c7d54a6cc
# Writes the Windows default Shell (explorer.exe) and a default Userinit under an
# HKCU-only Winlogon key. The rule must not alert on either.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'Shell' -Value 'explorer.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $key -Name 'Userinit' -Value 'C:\Windows\system32\userinit.exe,' -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
exit 0
