# Launches an inert executable under the requested names with the supplied
# command lines. ParentName optionally launches the child through another copy
# of the fixture. The delay gives ETW enrichment time to read the arguments.
function Invoke-AtomicCommandLines {
    param(
        [System.Collections.IDictionary]$Commands,
        [string]$ParentName
    )

    $dir = Join-Path $PWD "rustinel-atomic-$([Guid]::NewGuid().ToString('N'))"
    $fixture = Join-Path $dir 'fixture.exe'
    $source = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

public static class RustinelAtomicCommandLine {
    public static int Main(string[] args) {
        if (args.Length == 3 && args[0] == "--rustinel-atomic-child") {
            if (args[1] != Path.GetFileName(args[1])) {
                return 1;
            }
            var child = new ProcessStartInfo {
                FileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, args[1]),
                Arguments = Encoding.UTF8.GetString(Convert.FromBase64String(args[2])),
                UseShellExecute = false
            };
            using (var process = Process.Start(child)) {
                process.WaitForExit();
                return process.ExitCode;
            }
        }
        System.Threading.Thread.Sleep(2000);
        return 0;
    }
}
'@
    try {
        New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
        Add-Type -TypeDefinition $source -OutputAssembly $fixture -OutputType ConsoleApplication -ErrorAction Stop

        if ($ParentName) {
            $parent = Join-Path $dir $ParentName
            Copy-Item -LiteralPath $fixture -Destination $parent -ErrorAction Stop
        }

        foreach ($entry in $Commands.GetEnumerator()) {
            $bin = Join-Path $dir $entry.Key
            Copy-Item -LiteralPath $fixture -Destination $bin -ErrorAction Stop
            $arguments = $entry.Value
            if ($ParentName) {
                $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($arguments))
                $arguments = "--rustinel-atomic-child $($entry.Key) $encoded"
                $bin = $parent
            }
            $process = Start-Process -FilePath $bin -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
            if ($process.ExitCode -ne 0) {
                throw "Command-line fixture exited with code $($process.ExitCode)"
            }
        }
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
