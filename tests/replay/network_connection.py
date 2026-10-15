"""Check network_connection rules (Initiated, IP ranges, IPv6) with the real engine."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

LINUX = (
    "linux",
    "Outbound Network Connection from Shell Binary",
    "net_connection_lnx_shell_outbound.yml",
)
WINDOWS = (
    "windows",
    "Outbound Connection from Script or LOLBin Host",
    "net_connection_win_susp_lolbin_outbound.yml",
)

LINUX_SHELL = "/bin/bash"
WINDOWS_HOST = "C:\\Windows\\System32\\rundll32.exe"

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"

# (destination, expected alert). Non-public ranges must stay quiet; public must fire.
DESTINATIONS = [
    (PUBLIC_V4, True),
    (PUBLIC_V6, True),
    ("8.8.8.8", True),
    ("100.63.255.255", True),
    ("172.32.0.1", True),
    ("2001:4860:4860::8888", True),
    ("::ffff:93.184.216.34", True),
    ("10.1.2.3", False),
    ("172.16.5.5", False),
    ("172.31.255.255", False),
    ("192.168.1.10", False),
    ("127.0.0.1", False),
    ("169.254.169.254", False),
    ("100.64.0.1", False),
    ("0.0.0.0", False),
    ("224.0.0.251", False),
    ("239.255.255.250", False),
    ("255.255.255.255", False),
    ("192.0.2.1", False),
    ("198.51.100.7", False),
    ("203.0.113.9", False),
    ("198.18.0.1", False),
    ("::", False),
    ("::1", False),
    ("fe80::1", False),
    ("fd00::1", False),
    ("fc00::1234", False),
    ("ff02::fb", False),
    ("2001:db8::1", False),
    ("::ffff:10.1.2.3", False),
    ("::ffff:127.0.0.1", False),
    ("::ffff:192.168.1.10", False),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args = parser.parse_args()
    engine = args.engine.resolve()
    repo = Path(__file__).resolve().parents[2]
    version = json.loads((repo / "compatibility/engine.json").read_text())["version"]

    for platform, title, rule_file in (LINUX, WINDOWS):
        image = LINUX_SHELL if platform == "linux" else WINDOWS_HOST
        benign = "/usr/bin/curl" if platform == "linux" else "C:\\Windows\\System32\\svchost.exe"
        cases = []  # (image, destination, initiated, alert)
        for destination, alert in DESTINATIONS:
            cases.append((image, destination, True, alert))
            # Inbound / accepted connections never satisfy the outbound-only rule.
            cases.append((image, destination, False, False))
        # A non-listed process stays quiet on a public destination.
        cases.append((benign, PUBLIC_V4, True, False))
        # Missing Initiated must not alert.
        cases.append((image, PUBLIC_V4, None, False))

        events = []
        expected = set()
        timestamp = "2026-10-08T08:00:00Z"
        for index, (img, destination, initiated, alert) in enumerate(cases, 1):
            fields = {
                "ProcessId": str(index),
                "Image": img,
                "DestinationIp": destination,
                "DestinationPort": "443",
                "SourceIp": "192.168.1.5",
                "SourcePort": "50000",
                "Protocol": "tcp",
            }
            if initiated is not None:
                fields["Initiated"] = initiated
            events.append(
                {
                    "event_time": timestamp,
                    "ingest_seq": index,
                    "platform": platform,
                    "provider": "ebpf" if platform == "linux" else "etw",
                    "category": "Network",
                    "event_id": 3,
                    "opcode": 1,
                    "fields": fields,
                }
            )
            if alert:
                expected.add((index, title))

        with tempfile.TemporaryDirectory(prefix="rustinel-network-replay-") as directory:
            root = Path(directory)
            rules = root / "sigma"
            rules.mkdir()
            shutil.copyfile(repo / "rules/sigma" / platform / rule_file, rules / rule_file)
            payload = root / "cases.ndjson"
            data = "".join(json.dumps(event) + "\n" for event in events).encode()
            payload.write_bytes(data)
            payload.with_suffix(".manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "payload": payload.name,
                        "rustinel_version": version,
                        "platform": platform,
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
                [
                    str(engine),
                    "replay",
                    str(payload),
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                ],
                check=True,
                timeout=30,
            )
            alerts = [json.loads(line) for line in output.read_text().splitlines()]
            actual = {(alert["process.pid"], alert["rule.name"]) for alert in alerts}
            if actual != expected or len(alerts) != len(expected):
                raise RuntimeError(
                    f"{platform}: missing alerts: {sorted(expected - actual)}; "
                    f"unexpected alerts: {sorted(actual - expected)}"
                )
            print(
                f"Passed {len(cases)} {platform} network replay cases "
                f"({len(expected)} expected alerts)."
            )


if __name__ == "__main__":
    main()
