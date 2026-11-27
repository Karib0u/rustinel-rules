# Registers a fresh, unused per-user CLSID with a nonexistent DLL path.
$ErrorActionPreference = 'Stop'
$guid = [Guid]::NewGuid().ToString('B')
$clsid = "Software\Classes\CLSID\$guid"
$dll = "%LOCALAPPDATA%\RustinelAtomic-$guid\fixture.dll"
$userHive = [Microsoft.Win32.Registry]::CurrentUser

try {
    $server = $userHive.CreateSubKey("$clsid\InprocServer32")
    try {
        $server.SetValue('', $dll, [Microsoft.Win32.RegistryValueKind]::ExpandString)
        $option = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        if ($server.GetValue('', $null, $option) -ne $dll) {
            throw 'COM server value write verification failed'
        }
    } finally {
        $server.Dispose()
    }
} finally {
    $userHive.DeleteSubKeyTree($clsid, $false)
}
