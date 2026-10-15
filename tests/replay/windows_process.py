"""Check Windows process-creation rule logic with the real engine, without sensors.

Each case is a synthetic process-start event with the fields the Windows ETW
provider populates. The cases cover the positive spellings every corrected rule
must catch and the near-misses it must not.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

PROCDUMP = "LSASS Memory Dump via Procdump"
COMSVCS = "LSASS Memory Dump via comsvcs.dll MiniDump"
EVENTLOG = "Windows Event Log Cleared via Command Line"
IFM = "Active Directory Database (NTDS.dit) Extraction via ntdsutil IFM"
NTDS_COPY = "NTDS.dit Copied or Accessed with a File Tool"
ENCODED = "Suspicious Encoded PowerShell Command Line"
BITS = "BITS Job Download via bitsadmin"
WMIC = "WMI Process Execution via WMIC"
LOCALADMIN = "Local Account Created or Added to Administrators"

RULE_FILES = [
    "proc_creation_win_susp_procdump_lsass.yml",
    "proc_creation_win_susp_lsass_comsvcs_minidump.yml",
    "proc_creation_win_susp_eventlog_clear.yml",
    "proc_creation_win_susp_ntds_dit_extraction.yml",
    "proc_creation_win_susp_ntds_dit_copy.yml",
    "proc_creation_win_susp_encoded_powershell.yml",
    "proc_creation_win_susp_bitsadmin_download.yml",
    "proc_creation_win_susp_wmic_process_create.yml",
    "proc_creation_win_susp_local_admin_account_added.yml",
]

SYS = "C:\\Windows\\System32\\"
PS = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"

# (image, command line, original file name or None, rule title that must alert or None)
CASES = [
    # Procdump: tool + LSASS target + dump flag.
    (r"C:\tools\procdump.exe", "procdump.exe -accepteula -ma lsass.exe lsass.dmp", None, PROCDUMP),
    (r"C:\tools\procdump64.exe", "procdump64.exe -mm lsass C:\\x.dmp", None, PROCDUMP),
    (r"C:\tools\procdump.exe", 'procdump.exe /ma "lsass.exe" x.dmp', None, PROCDUMP),
    (r"C:\temp\svc.exe", "svc.exe -ma lsass.exe x.dmp", "procdump", PROCDUMP),  # renamed binary
    (r"C:\tools\procdump.exe", "procdump.exe -ma notepad.exe notepad.dmp", None, None),
    (r"C:\tools\procdump.exe", "procdump.exe -ma notepad.exe lsass_notes.dmp", None, None),
    (r"C:\tools\procdump.exe", "procdump.exe -accepteula lsass.exe", None, None),  # no dump flag
    (r"C:\temp\svc.exe", "svc.exe -ma lsass.exe x.dmp", None, None),  # no tool identity
    # comsvcs: rundll32 + comsvcs.dll + adjacent export.
    (
        SYS + "rundll32.exe",
        r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 x.dmp full",
        None,
        COMSVCS,
    ),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll,#24 624 x.dmp full", None, COMSVCS),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll, #+000024 624 x.dmp full", None, COMSVCS),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll #-4294967272 624 x.dmp full", None, COMSVCS),
    (r"C:\temp\r.exe", r"r.exe comsvcs.dll, MiniDump 624 x.dmp full", "RUNDLL32.EXE", COMSVCS),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll, #240 624 x.dmp full", None, None),
    (SYS + "rundll32.exe", r"rundll32.exe comsvcs.dll, #124 624 x.dmp full", None, None),
    (SYS + "rundll32.exe", r"rundll32.exe shell32.dll,Control_RunDLL minidump comsvcs", None, None),
    (SYS + "notepad.exe", r"notepad.exe comsvcs.dll, MiniDump", None, None),  # not rundll32
    # Event log clear: per-branch process identity.
    (SYS + "wevtutil.exe", "wevtutil.exe cl Security", None, EVENTLOG),
    (SYS + "wevtutil.exe", "wevtutil.exe clear-log System", None, EVENTLOG),
    (PS, 'powershell.exe -Command "Clear-EventLog -LogName Application"', None, EVENTLOG),
    (r"C:\Program Files\PowerShell\7\pwsh.exe", 'pwsh.exe -c "$l.ClearEventLog()"', None, EVENTLOG),
    (
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        'pwsh.exe -c "Get-EventLog -LogName Security -Newest 5"',
        None,
        None,
    ),
    (SYS + "wevtutil.exe", "wevtutil.exe qe Security /c:5", None, None),
    (SYS + "wevtutil.exe", "wevtutil.exe epl Security C:\\cl\\sec.evtx", None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo Clear-EventLog", None, None),  # not a PowerShell host
    (SYS + "findstr.exe", "findstr.exe Clear-EventLog script.ps1", None, None),
    # NTDS IFM (ntdsutil) vs copy/access (separate rule).
    (SYS + "ntdsutil.exe", 'ntdsutil.exe "ac i ntds" "ifm" "create full C:\\ifm" q q', None, IFM),
    (SYS + "ntdsutil.exe", "ntdsutil.exe ifm create sysvol full C:\\ifm", None, IFM),
    (SYS + "ntdsutil.exe", 'ntdsutil.exe "ac i ntds" "files" info q q', None, None),
    (SYS + "ntdsutil.exe", 'ntdsutil.exe "ac i ntds" q q', None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo ifm create full", None, None),
    (
        SYS + "esentutl.exe",
        r"esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\x\ntds.dit",
        None,
        NTDS_COPY,
    ),
    (
        SYS + "cmd.exe",
        r"cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\NTDS\ntds.dit C:\x",
        None,
        NTDS_COPY,
    ),
    (PS, r"powershell.exe -c Copy-Item C:\Windows\NTDS\ntds.dit C:\x", None, NTDS_COPY),
    (SYS + "robocopy.exe", r"robocopy.exe C:\vss\Windows\NTDS C:\x ntds.dit", None, NTDS_COPY),
    (SYS + "cmd.exe", "cmd.exe /c echo ntds.dit", None, None),
    (SYS + "findstr.exe", "findstr.exe ntds.dit notes.txt", None, None),
    (
        SYS + "esentutl.exe",
        r"esentutl.exe /mh C:\Windows\NTDS\ntds.dit",
        None,
        None,
    ),  # header dump, no copy
    (SYS + "esentutl.exe", r"esentutl.exe /y C:\a.edb /d C:\b.edb", None, None),
    # Encoded PowerShell: whole-argument boundaries only.
    (PS, "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe -enc VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe -e VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe -ec VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe -encodedcomman VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe /EncodedCommand VwByAGkAdABlAA==", None, ENCODED),
    (PS, "powershell.exe \u2013enc VwByAGkAdABlAA==", None, ENCODED),
    (PS, 'powershell.exe -nop -w hidden -ENC "VwByAGkAdABlAA=="', None, ENCODED),
    (r"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh.exe -en VwByAGkAdABlAA==", None, ENCODED),
    (r"C:\temp\ps.exe", "ps.exe -enc VwByAGkAdABlAA==", "PowerShell.EXE", ENCODED),
    (PS, 'powershell.exe -Command "Get-Content a.txt -Encoding UTF8"', None, None),
    (PS, "powershell.exe -ExecutionPolicy Bypass -File run.ps1", None, None),
    (PS, "powershell.exe -encoding UTF8 -Command dir", None, None),
    (PS, "powershell.exe -encx VwByAGkAdABlAA==", None, None),
    (PS, "powershell.exe -ep Bypass -Command dir", None, None),
    (PS, "powershell.exe -Command dir -e-nc", None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo -enc VwByAGkAdABlAA==", None, None),
    # BITS: remote-source direct transfer, not job management.
    (
        SYS + "bitsadmin.exe",
        "bitsadmin.exe /transfer job1 http://example.test/a.exe C:\\a.exe",
        None,
        BITS,
    ),
    (
        SYS + "bitsadmin.exe",
        "bitsadmin /transfer job1 /download /priority high https://example.test/a C:\\a",
        None,
        BITS,
    ),
    (SYS + "bitsadmin.exe", "bitsadmin /addfile job1 ftp://example.test/a C:\\a", None, BITS),
    (r"C:\temp\b.exe", "b.exe -transfer j http://example.test/a C:\\a", "bitsadmin.exe", BITS),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /create httpjob", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /create /download job1", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /list /allusers", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /resume job1", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /transfer job1 C:\\src.bin C:\\dst.bin", None, None),
    (SYS + "bitsadmin.exe", "bitsadmin.exe /addfile job1 C:\\httpdocs\\a C:\\b", None, None),
    (
        SYS + "cmd.exe",
        "cmd.exe /c echo bitsadmin /transfer j http://example.test/a C:\\a",
        None,
        None,
    ),
    # WMIC: ordered process / call / create.
    (SYS + "wbem\\WMIC.exe", 'wmic.exe process call create "cmd.exe /c calc"', None, WMIC),
    (SYS + "wbem\\WMIC.exe", 'wmic.exe /node:srv01 process call create "cmd.exe"', None, WMIC),
    (SYS + "wbem\\WMIC.exe", "wmic.exe PROCESS CALL CREATE notepad", None, WMIC),
    (r"C:\temp\w.exe", "w.exe process call create calc", "wmic.exe", WMIC),
    (SYS + "wbem\\WMIC.exe", "wmic.exe process list brief", None, None),
    (SYS + "wbem\\WMIC.exe", "wmic.exe process where name=cmd.exe get processid", None, None),
    (SYS + "wbem\\WMIC.exe", "wmic.exe service call create", None, None),
    (SYS + "wbem\\WMIC.exe", "wmic.exe create call process", None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo process call create", None, None),
    # Local accounts: `user` is the net subcommand; a group name containing it is not.
    (SYS + "net.exe", "net.exe user bob P@ssw0rd! /add", None, LOCALADMIN),
    (SYS + "net1.exe", "net1 user /add bob", None, LOCALADMIN),
    (SYS + "net.exe", 'net.exe localgroup "Administrators" bob /add', None, LOCALADMIN),
    (SYS + "net.exe", 'net.exe localgroup "Remote Desktop Users" bob /add', None, None),
    (SYS + "net.exe", "net.exe localgroup Users bob /add", None, None),
    (SYS + "net.exe", "net.exe user bob", None, None),
    (SYS + "net.exe", "net.exe user bob /delete", None, None),
    (SYS + "cmd.exe", "cmd.exe /c echo net user bob /add", None, None),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args = parser.parse_args()
    engine = args.engine.resolve()
    repo = Path(__file__).resolve().parents[2]
    timestamp = "2026-10-08T08:00:00Z"
    events = []
    expected = set()
    for index, (image, command_line, original, title) in enumerate(CASES, 1):
        fields = {
            "ProcessId": str(index),
            "Image": image,
            "CommandLine": command_line,
            "ParentImage": SYS + "cmd.exe",
        }
        if original is not None:
            fields["OriginalFileName"] = original
        events.append(
            {
                "event_time": timestamp,
                "ingest_seq": index,
                "platform": "windows",
                "provider": "etw",
                "category": "Process",
                "event_id": 1,
                "opcode": 1,
                "fields": fields,
            }
        )
        if title is not None:
            expected.add((index, title))

    with tempfile.TemporaryDirectory(prefix="rustinel-windows-process-replay-") as directory:
        root = Path(directory)
        rules = root / "sigma"
        rules.mkdir()
        for name in RULE_FILES:
            shutil.copyfile(repo / "rules/sigma/windows" / name, rules / name)
        payload = root / "cases.ndjson"
        data = "".join(json.dumps(event) + "\n" for event in events).encode()
        payload.write_bytes(data)
        payload.with_suffix(".manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "payload": payload.name,
                    "rustinel_version": json.loads(
                        (repo / "compatibility/engine.json").read_text()
                    )["version"],
                    "platform": "windows",
                    "started_at": timestamp,
                    "ended_at": timestamp,
                    "status": "complete",
                    "events": {
                        "received": len(events),
                        "written": len(events),
                        "lost": 0,
                        "source_lost": 0,
                    },
                    "payload_bytes": len(data),
                    "payload_sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        )
        config = root / "config.toml"
        config.write_text(
            f"[scanner]\nsigma_rules_path = {json.dumps(str(rules))}\n"
            'sigma_match_mode = "all"\nyara_enabled = false\n'
            "[ioc]\nenabled = false\n[dedup]\nenabled = false\n"
            f"[logging]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
            f"[alerts]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
        )
        output = root / "alerts.ndjson"
        subprocess.run(
            [str(engine), "replay", str(payload), "--config", str(config), "--output", str(output)],
            check=True,
            timeout=60,
        )
        alerts = [json.loads(line) for line in output.read_text().splitlines()]
        actual = {(alert["process.pid"], alert["rule.name"]) for alert in alerts}
        if actual != expected or len(alerts) != len(expected):
            missing = sorted((i, t, CASES[i - 1][1]) for i, t in expected - actual)
            unexpected = sorted((i, t, CASES[i - 1][1]) for i, t in actual - expected)
            raise RuntimeError(f"Missing alerts: {missing}; unexpected alerts: {unexpected}")
        print(
            f"Passed {len(CASES)} Windows process replay cases ({len(expected)} expected alerts)."
        )


if __name__ == "__main__":
    main()
