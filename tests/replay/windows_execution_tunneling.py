"""Replay Windows execution, tunneling and evasion with inert event data."""

import argparse
from pathlib import Path

from advanced_negatives import build_events, lib, replay

CERTUTIL = r"C:\Windows\System32\certutil.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

POSITIVES = {
    "image_load_win_dotnet_script_host.yml": [
        {
            "Image": r"C:\Windows\System32\wscript.exe",
            "ImageLoaded": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\CLR.dll",
        },
        {
            "Image": r"C:\Windows\SysWOW64\cscript.exe",
            "ImageLoaded": r"C:\Windows\SysWOW64\mscoree.dll",
        },
        {
            "Image": r"\Device\HarddiskVolume2\Windows\System32\MSHTA.EXE",
            "ImageLoaded": r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll",
        },
    ],
    "proc_creation_win_certutil_decode.yml": [
        {
            "Image": CERTUTIL,
            "CommandLine": r'certutil.exe -f -DECODE "C:\Build Staging\in.b64" ".\out file.exe"',
        },
        {
            "Image": CERTUTIL,
            "CommandLine": r'certutil "-decodehex" C:\Lab\in.hex "D:\Project\out.PS1" 4',
        },
        {
            "Image": CERTUTIL,
            "CommandLine": r'certutil -decode C:\Lab\in.b64 "D:\Users\Lab User\Downloads\a.dat"',
        },
        {
            "Image": CERTUTIL,
            "CommandLine": r"certutil -decode C:\Lab\in.b64 C:\Windows\Temp\a.bin",
        },
        {
            "Image": r"C:\Tools\decode.exe",
            "OriginalFileName": "CertUtil.exe",
            "CommandLine": r"decode.exe -decode source.b64 C:\ProgramData\Lab\out.tmp",
        },
    ],
    "file_event_win_web_root_script_create.yml": [
        {"Image": POWERSHELL, "TargetFilename": path}
        for path in (
            r"C:\inetpub\wwwroot\site\index.asp",
            r"\Device\HarddiskVolume2\inetpub\wwwroot\Default.ASPX",
            r"D:\xampp\htdocs\app\index.php",
            r"C:\wamp\www\site\index.jsp",
            r"D:\Sites\Apache24\htdocs\admin\index.jspx",
            r"D:\Apache\htdocs\api\handler.ashx",
        )
    ]
    + [
        {
            "Image": r"C:\Users\Public\msdeploy.exe",
            "TargetFilename": r"C:\inetpub\wwwroot\Default.aspx",
        },
        {"TargetFilename": r"C:\xampp\htdocs\index.php"},
    ],
    "ps_script_win_reverse_shell.yml": [
        {"ScriptBlockText": "# [System.Net.Sockets.TCPClient]\n# .GetStream()\n# iex $placeholder"},
        {
            "ScriptBlockText": (
                "# [Net.Sockets.Socket]\n# [System.IO.StreamReader]\n"
                "# [scriptblock]::Create($placeholder)"
            )
        },
        {
            "ScriptBlockText": (
                "# [Net.Sockets.TcpClient]\n# [StreamWriter]\n# cmd.exe\n"
                "# RedirectStandardInput\n# RedirectStandardOutput"
            )
        },
    ],
    "proc_creation_win_tunneling_tools.yml": [
        {"Image": r"C:\Tools\NGROK.EXE"},
        {"Image": r"C:\Tools\agent.exe", "OriginalFileName": "chisel.exe"},
        {"CommandLine": r'"C:\Program Files\frp\frpc.exe" --config fixture.toml'},
        {
            "Image": r"C:\Tools\cloudflared-windows-amd64.exe",
            "CommandLine": (
                r'cloudflared-windows-amd64.exe tunnel --config "C:\Lab Files\cf.yml" run fixture'
            ),
        },
        {"CommandLine": "cloudflared --no-autoupdate tunnel --url=INERT_FIXTURE"},
        {
            "Image": r"C:\Tools\connector.exe",
            "OriginalFileName": "Cloudflared.exe",
            "CommandLine": "connector.exe tunnel run fixture",
        },
        {"CommandLine": "plink.exe -batch -R INERT_FIXTURE"},
        {
            "Image": r"C:\Tools\ssh-client.exe",
            "OriginalFileName": "Plink.exe",
            "CommandLine": 'ssh-client.exe "-R" INERT_FIXTURE',
        },
    ],
}

NEAR_MISSES = {
    "image_load_win_dotnet_script_host.yml": [
        {
            "Image": r"C:\Windows\System32\wscript.exe",
            "ImageLoaded": r"C:\Tools\acme-clr.dll",
        },
        {
            "Image": r"C:\Tools\acme-cscript.exe",
            "ImageLoaded": r"C:\Windows\System32\mscoree.dll",
        },
    ],
    "proc_creation_win_certutil_decode.yml": [
        {
            "Image": CERTUTIL,
            "CommandLine": r"certutil -decodehelper C:\Lab\source.b64 C:\Temp\example.exe",
        },
        {
            "Image": CERTUTIL,
            "CommandLine": r'certutil -decode source.b64 "C:\Program Files\Vendor\Temp\out.bin"',
        },
        {
            "Image": CERTUTIL,
            "CommandLine": r"certutil -decode C:\Lab\source.b64 C:\Lab\payload.exe.b64",
        },
        {
            "Image": CERTUTIL,
            "CommandLine": r'certutil -encode "notes -decode input.b64 output.exe" notes.b64',
        },
    ],
    "file_event_win_web_root_script_create.yml": [
        {"TargetFilename": r"C:\Archive\notapache\htdocs\index.php"},
        {"TargetFilename": r"C:\inetpub\wwwroot_backup\Default.aspx"},
    ],
    "ps_script_win_reverse_shell.yml": [
        {"ScriptBlockText": "# [Net.Sockets.SocketFlags]\n# .GetStream()\n# iex $placeholder"},
        {
            "ScriptBlockText": (
                "# [Net.Sockets.Socket]\n# [System.IO.StreamReader]\n"
                "# cmd.exe\n# RedirectStandardOutput"
            )
        },
    ],
    "proc_creation_win_tunneling_tools.yml": [
        {"CommandLine": "plink.exe -r INERT_FIXTURE"},
        {"CommandLine": "plink.exe -L INERT_FIXTURE"},
        {"CommandLine": 'cloudflared.exe access login "tunnel run"'},
        {"CommandLine": "cloudflared.exe tunnel run --help"},
    ],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    rules = {artifact.path.name: artifact for artifact in lib.load_all_artifacts()}
    for filename, positives in POSITIVES.items():
        rule = rules[filename]
        title = rule.meta["title"]
        cases = [{"fields": fields} for fields in positives + NEAR_MISSES[filename]]
        cases.extend(rule.meta["rustinel"]["negatives"])
        events = build_events(rule, cases)
        if rule.meta["logsource"]["category"] == "file_event":
            for event in events:
                event["opcode"] = 64  # Kernel-File create
            # The same path during a write, rename or deletion is not a create.
            for event_id, opcode in [(65, 65), (71, 71), (23, 70)]:
                pid = len(events) + 1
                events.append(
                    events[0]
                    | {
                        "event_id": event_id,
                        "opcode": opcode,
                        "ingest_seq": pid,
                        "fields": {"ProcessId": str(pid), **positives[0]},
                    }
                )
        alerts = replay(engine, rule, events)
        actual = sorted(
            int(alert["process.pid"]) for alert in alerts if alert["rule.name"] == title
        )
        expected = list(range(1, len(positives) + 1))
        if actual != expected:
            raise RuntimeError(f"{filename}: expected PIDs {expected}, got {actual}")
        benign = len(events) - len(positives)
        print(f"Passed {len(positives)} positive and {benign} benign cases: {title}")


if __name__ == "__main__":
    main()
