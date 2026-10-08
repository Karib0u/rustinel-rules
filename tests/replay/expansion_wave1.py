"""Check the measured-expansion wave 1 rules (#60) with the real engine, without sensors.

Each case is one synthetic event; positives must alert and the near-misses next
to them must not. The mass-rename correlation is replayed separately because it
needs many events from one process.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

TIMESTAMP = "2026-10-08T08:00:00Z"
PROVIDERS = {"windows": "etw", "linux": "ebpf", "macos": "esf"}

AMSI = "AMSI Provider Registration Removed"
PREFETCH = "Prefetch or Event Log File Deleted"
RENAMED = "Renamed System Binary Execution"
TIMESTOMP = "File Timestamp Changed by Script Host"
SUID = "Shell Running as Root Through a SUID Binary"
SHELL_NET = "Outbound Network Connection from Shell Binary (macOS)"
TUNNEL = {
    "windows": "DNS Query to Tunnel Service",
    "linux": "DNS Query to Tunnel Service (Linux)",
    "macos": "DNS Query to Tunnel Service (macOS)",
}
BASE = {
    "windows": "File Renamed to Ransomware-Style Extension",
    "linux": "File Renamed to Ransomware-Style Extension (Linux)",
    "macos": "File Renamed to Ransomware-Style Extension (macOS)",
}
MASS = {
    "windows": "Mass File Rename to Ransomware-Style Extension",
    "linux": "Mass File Rename to Ransomware-Style Extension (Linux)",
    "macos": "Mass File Rename to Ransomware-Style Extension (macOS)",
}

RULE_FILES = {
    "windows": [
        "registry_delete_win_susp_amsi_provider_removed.yml",
        "file_delete_win_susp_prefetch_evtx_deleted.yml",
        "proc_creation_win_susp_renamed_system_binary.yml",
        "file_change_win_hunting_timestomp_script_host.yml",
        "dns_query_win_susp_tunnel_service.yml",
        "file_rename_win_ransomware_extension_base.yml",
        "file_rename_win_ransomware_mass_rename.yml",
    ],
    "linux": [
        "proc_creation_lnx_suid_shell_euid0.yml",
        "dns_query_lnx_susp_tunnel_service.yml",
        "file_rename_lnx_ransomware_extension_base.yml",
        "file_rename_lnx_ransomware_mass_rename.yml",
    ],
    "macos": [
        "net_connection_macos_shell_outbound.yml",
        "dns_query_macos_susp_tunnel_service.yml",
        "file_rename_macos_ransomware_extension_base.yml",
        "file_rename_macos_ransomware_mass_rename.yml",
    ],
}

SYS = "C:\\Windows\\System32\\"
PS = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
TUNNEL_DOMAINS = [
    "abc123.ngrok.io",
    "abc123.ngrok-free.app",
    "abc123.ngrok.app",
    "abc123.ngrok-free.dev",
    "random-words.trycloudflare.com",
    "myhost.serveo.net",
    "myhost.loca.lt",
    "abc.a.pinggy.io",
    "abc.pinggy.link",
    "0.bore.pub",
    "ABC123.NGROK.IO",
]
BENIGN_DOMAINS = [
    "example.com",
    "cloudflare.com",
    "notngrok.io",
    "ngrok.com.example.org",
    "fakeloca.lt",
    "mytrycloudflare.com",
    "bore.pub.example.net",
]
RANSOM_RENAMES = [
    "report.docx.locked",
    "photo.jpg.encrypted",
    "a.xlsx.crypted",
    "a.xlsx.CRYPT",
    "a.xlsx.enc",
    "a.pdf.rustinel-locked",
    "a.pdf.id-1234.ransom",
    "a.pdf.lockbit",
    "a.pdf.WNCRY",
]
BENIGN_RENAMES = [
    "report.docx",
    "report.docx.bak",
    "yarn.lock",
    "notes.encoding",
    "a.pdf.tmp",
    "locked.txt",
    "a.pdf.encoded",
]


def process(fields):
    return ("Process", 1, 1, fields)


def cases(platform):
    """(category, event_id, opcode, fields, rule title that must alert or None)."""
    out = []
    for domain in TUNNEL_DOMAINS:
        out.append(("Dns", 22, 1, {"QueryName": domain}, TUNNEL[platform]))
    for domain in BENIGN_DOMAINS:
        out.append(("Dns", 22, 1, {"QueryName": domain}, None))
    if platform == "windows":
        pf = "C:\\Windows\\Prefetch\\"
        logs = "C:\\Windows\\System32\\winevt\\Logs\\"
        # AMSI provider key (opcode 38/41 are the registry delete opcodes).
        amsi = "HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers\\"
        for target in (
            amsi + "{00000000-1111-2222-3333-444444444444}",
            amsi + "{x}\\InprocServer32",
        ):
            out.append(("Registry", 12, 38, {"TargetObject": target, "Image": PS}, AMSI))
        out.append(("Registry", 12, 41, {"TargetObject": amsi + "{x}\\Name", "Image": PS}, AMSI))
        out.append(("Registry", 12, 38, {"TargetObject": "HKLM\\SOFTWARE\\Vendor\\Key"}, None))
        out.append(
            (
                "Registry",
                12,
                38,
                {"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\AMSIx\\Providers"},
                None,
            )
        )
        # Only a delete matches; creating the key does not.
        out.append(("Registry", 12, 36, {"TargetObject": amsi + "{x}", "Image": PS}, None))
        out.append(("Registry", 13, 39, {"TargetObject": amsi + "{x}\\Name", "Image": PS}, None))
        # Prefetch and event logs.
        for target in (
            pf + "CALC.EXE-0F2D0A1B.pf",
            pf + "evil.exe-AAAA.PF",
            logs + "Security.evtx",
        ):
            out.append(("File", 23, 70, {"TargetFilename": target, "Image": PS}, PREFETCH))
        out.append(("File", 23, 70, {"TargetFilename": pf + "Layout.ini", "Image": PS}, None))
        out.append(
            ("File", 23, 70, {"TargetFilename": "C:\\Users\\a\\Desktop\\x.pf", "Image": PS}, None)
        )
        out.append(
            ("File", 23, 70, {"TargetFilename": logs + "Security.evtx.bak", "Image": PS}, None)
        )
        out.append(
            ("File", 23, 70, {"TargetFilename": pf + "OLD.EXE-1.pf", "Image": "System"}, None)
        )
        out.append(
            (
                "File",
                23,
                70,
                {"TargetFilename": logs + "Archive.evtx", "Image": SYS + "svchost.exe"},
                None,
            )
        )
        out.append(("File", 11, 64, {"TargetFilename": pf + "NEW.EXE-1.pf", "Image": PS}, None))
        # Renamed system binaries: OriginalFileName vs Image.
        pairs = [
            ("PowerShell.EXE", "C:\\Users\\a\\AppData\\Local\\Temp\\upd.exe", RENAMED),
            ("Cmd.Exe", "C:\\ProgramData\\svc.exe", RENAMED),
            ("MSHTA.EXE", "C:\\Temp\\x.exe", RENAMED),
            ("RUNDLL32.EXE", "C:\\Temp\\r32.exe", RENAMED),
            ("CertUtil.exe", "C:\\Temp\\cu.exe", RENAMED),
            ("MSBuild.exe", "C:\\Temp\\mb.exe", RENAMED),
            ("PowerShell.EXE", PS, None),
            (
                "PowerShell.EXE",
                "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
                None,
            ),
            ("Cmd.Exe", SYS + "cmd.exe", None),
            ("RUNDLL32.EXE", "C:\\Windows\\SysWOW64\\rundll32.exe", None),
            (
                "MSBuild.exe",
                "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
                None,
            ),
            ("notepad.exe", "C:\\Temp\\notes.exe", None),
            ("Teams.exe", "C:\\Temp\\teams.exe", None),
        ]
        for original, image, title in pairs:
            out.append(process({"Image": image, "OriginalFileName": original}) + (title,))
        out.append(process({"Image": "C:\\Temp\\bare.exe"}) + (None,))
        # Timestomp (file_change = Sysmon event 2).
        out.append(
            ("File", 2, 2, {"TargetFilename": "C:\\Temp\\payload.exe", "Image": PS}, TIMESTOMP)
        )
        out.append(
            (
                "File",
                2,
                2,
                {"TargetFilename": "C:\\Temp\\run.ps1", "Image": SYS + "wscript.exe"},
                TIMESTOMP,
            )
        )
        out.append(("File", 2, 2, {"TargetFilename": "C:\\Temp\\notes.txt", "Image": PS}, None))
        out.append(
            (
                "File",
                2,
                2,
                {"TargetFilename": "C:\\Temp\\payload.exe", "Image": SYS + "notepad.exe"},
                None,
            )
        )
        out.append(("File", 11, 64, {"TargetFilename": "C:\\Temp\\payload.exe", "Image": PS}, None))
        out.append(("File", 65, 65, {"TargetFilename": "C:\\Temp\\payload.exe", "Image": PS}, None))
    if platform == "linux":
        shell = "/usr/bin/bash"
        for image in (shell, "/bin/sh", "/tmp/x/bash", "/usr/bin/zsh"):
            out.append(
                process({"Image": image, "RealUserId": "1000", "EffectiveUserId": "0"}) + (SUID,)
            )
        out.append(
            process({"Image": shell, "RealUserId": "65534", "EffectiveUserId": "0"}) + (SUID,)
        )
        out.append(
            process({"Image": shell, "RealUserId": "0", "EffectiveUserId": "0"}) + (None,)
        )  # sudo
        out.append(
            process({"Image": shell, "RealUserId": "1000", "EffectiveUserId": "1000"}) + (None,)
        )
        out.append(process({"Image": shell, "RealUserId": "1000"}) + (None,))  # euid not reported
        out.append(
            process({"Image": "/usr/bin/passwd", "RealUserId": "1000", "EffectiveUserId": "0"})
            + (None,)
        )
        out.append(
            process({"Image": "/usr/bin/sudo", "RealUserId": "1000", "EffectiveUserId": "0"})
            + (None,)
        )
        out.append(
            process({"Image": "/usr/bin/su", "RealUserId": "1000", "EffectiveUserId": "0"})
            + (None,)
        )
        out.append(
            process({"Image": "/usr/bin/pkexec", "RealUserId": "1000", "EffectiveUserId": "0"})
            + (None,)
        )
    if platform == "macos":
        shell_images = ["/bin/bash", "/bin/zsh", "/private/tmp/x/bash", "/opt/homebrew/bin/bash"]
        for image in shell_images:
            out.append(("Network", 3, 1, net_fields(image, "93.184.216.34"), SHELL_NET))
        out.append(
            (
                "Network",
                3,
                1,
                net_fields("/bin/bash", "2606:2800:220:1:248:1893:25c8:1946"),
                SHELL_NET,
            )
        )
        out.append(("Network", 3, 1, net_fields("/bin/bash", "10.1.2.3"), None))
        out.append(("Network", 3, 1, net_fields("/bin/zsh", "192.168.1.10"), None))
        out.append(("Network", 3, 1, net_fields("/bin/zsh", "127.0.0.1"), None))
        out.append(("Network", 3, 1, net_fields("/bin/bash", "::1"), None))
        out.append(("Network", 3, 1, net_fields("/usr/bin/curl", "93.184.216.34"), None))
        out.append(("Network", 3, 1, net_fields("/usr/bin/ssh", "93.184.216.34"), None))
        out.append(
            (
                "Network",
                3,
                1,
                net_fields("/Applications/Safari.app/Contents/MacOS/Safari", "8.8.8.8"),
                None,
            )
        )
    # Mass-rename base rule: only ransomware-style extensions match.
    for name in RANSOM_RENAMES:
        out.append(rename_case(platform, name) + (BASE[platform],))
    for name in BENIGN_RENAMES:
        out.append(rename_case(platform, name) + (None,))
    return out


def net_fields(image, destination):
    return {
        "Image": image,
        "DestinationIp": destination,
        "DestinationPort": "443",
        "SourceIp": "192.168.1.5",
        "SourcePort": "50000",
        "Protocol": "tcp",
    }


def rename_case(platform, name):
    root = "C:\\Users\\a\\Documents\\" if platform == "windows" else "/home/a/docs/"
    fields = {
        "Image": "/usr/bin/mv" if platform != "windows" else PS,
        "TargetFilename": root + name,
    }
    if platform != "windows":
        fields["SourceFilename"] = root + "orig"
    return ("File", 71, 71, fields)


def mass_events(platform):
    """(pid, number of renames, extension) groups for the correlation."""
    return [
        (5000, 49, "locked"),  # one short of the threshold
        (5001, 50, "locked"),  # exactly the threshold
        (5002, 120, "bak"),  # many renames, none to a ransomware extension
        (5003, 30, "locked"),  # two processes sharing the work stay under
        (5004, 30, "locked"),
        (5005, 75, "rustinel-locked"),
    ]


def make_event(index, platform, category, event_id, opcode, fields, timestamp=TIMESTAMP):
    return {
        "event_time": timestamp,
        "ingest_seq": index,
        "platform": platform,
        "provider": PROVIDERS[platform],
        "category": category,
        "event_id": event_id,
        "opcode": opcode,
        "fields": fields,
    }


def run_engine(engine, repo, platform, rule_files, events):
    with tempfile.TemporaryDirectory(prefix=f"rustinel-{platform}-wave1-replay-") as directory:
        root = Path(directory)
        rules = root / "sigma"
        rules.mkdir()
        for name in rule_files:
            shutil.copyfile(repo / "rules/sigma" / platform / name, rules / name)
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
                    "platform": platform,
                    "started_at": TIMESTAMP,
                    "ended_at": TIMESTAMP,
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
            capture_output=True,
        )
        return [json.loads(line) for line in output.read_text().splitlines()]


def replay_single_events(engine, repo, platform):
    events, expected = [], set()
    # Correlation rules load with their base but never fire on unique events.
    for index, (category, event_id, opcode, fields, title) in enumerate(cases(platform), 1):
        events.append(
            make_event(
                index, platform, category, event_id, opcode, {"ProcessId": str(index), **fields}
            )
        )
        if title is not None:
            expected.add((index, title))
    alerts = run_engine(engine, repo, platform, RULE_FILES[platform], events)
    actual = {(int(alert["process.pid"]), alert["rule.name"]) for alert in alerts}
    if actual != expected or len(alerts) != len(expected):
        raise RuntimeError(
            f"{platform}: missing alerts: {sorted(expected - actual)}; "
            f"unexpected alerts: {sorted(actual - expected)}"
        )
    return len(events), len(expected)


def replay_mass_rename(engine, repo, platform):
    events = []
    for pid, count, extension in mass_events(platform):
        for number in range(count):
            _, _, _, fields = rename_case(platform, f"f{number}.docx.{extension}")
            events.append(
                make_event(
                    len(events) + 1,
                    platform,
                    "File",
                    71,
                    71,
                    {"ProcessId": str(pid), **fields},
                )
            )
    alerts = run_engine(engine, repo, platform, RULE_FILES[platform], events)
    mass = [alert for alert in alerts if alert["rule.name"] == MASS[platform]]
    fired = Counter(int(alert["process.pid"]) for alert in mass)
    # 5001 reaches the threshold exactly; 5005 reaches it and the engine may
    # alert again on later matches, so only require at least one.
    if set(fired) != {5001, 5005}:
        raise RuntimeError(
            f"{platform}: mass-rename correlation fired for pids {sorted(fired)}, "
            "expected exactly 5001 and 5005"
        )
    return len(events), len(mass)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--platform", choices=sorted(RULE_FILES), action="append")
    args = parser.parse_args()
    engine = args.engine.resolve()
    repo = Path(__file__).resolve().parents[2]
    for platform in args.platform or sorted(RULE_FILES):
        total, positives = replay_single_events(engine, repo, platform)
        print(f"Passed {total} {platform} wave 1 cases ({positives} expected alerts).")
        total, alerts = replay_mass_rename(engine, repo, platform)
        print(f"Passed {total} {platform} mass-rename events ({alerts} correlation alerts).")


if __name__ == "__main__":
    main()
