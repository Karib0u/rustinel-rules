# Launches an inert executable under the requested names with the supplied
# command lines. The delay gives the ETW enrichment time to read the arguments.
function Invoke-AtomicCommandLines {
    param([System.Collections.IDictionary]$Commands)

    $dir = Join-Path $PWD "rustinel-atomic-$([Guid]::NewGuid().ToString('N'))"
    $fixture = Join-Path $dir 'fixture.exe'
    $source = @'
public static class RustinelAtomicCommandLine {
    public static void Main() {
        System.Threading.Thread.Sleep(2000);
    }
}
'@
    try {
        New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
        Add-Type -TypeDefinition $source -OutputAssembly $fixture -OutputType ConsoleApplication -ErrorAction Stop

        foreach ($entry in $Commands.GetEnumerator()) {
            $bin = Join-Path $dir $entry.Key
            Copy-Item -LiteralPath $fixture -Destination $bin -ErrorAction Stop
            Start-Process -FilePath $bin -ArgumentList $entry.Value -Wait -ErrorAction Stop
        }
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
