"""Check container-unpacking exclusions with the real engine, without sensors."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

RULES = {
    "systemd": ("Systemd Unit Persistence", "/usr/lib/systemd/system/apt-daily.timer"),
    "cron": ("Cron Job Persistence", "/etc/cron.daily/dpkg"),
    "shell_profile": ("Shell Profile / RC File Persistence", "/etc/skel/.bashrc"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args = parser.parse_args()
    engine = args.engine.resolve()
    engine_version = (
        subprocess.run(
            [str(engine), "--version"], check=True, capture_output=True, text=True, timeout=10
        )
        .stdout.strip()
        .removeprefix("rustinel ")
    )
    repo = Path(__file__).resolve().parents[2]
    cases = []
    for title, suffix in RULES.values():
        for image in ("/usr/bin/containerd", "/usr/bin/dockerd"):
            for storage in (
                "/var/lib/containerd/tmpmounts/layer",
                "/var/lib/docker/overlay2/layer/diff",
            ):
                cases.append((title, image, storage + suffix, False))
            # Runtime writes to actual host persistence paths must still alert.
            cases.append((title, image, suffix, True))
        for image in ("/bin/sh", "/tmp/attacker", None):
            cases.append((title, image, suffix, True))
            cases.append((title, image, "/var/lib/containerd/tmpmounts/layer" + suffix, True))
        cases.extend(
            [
                (title, "/usr/bin/containerd", "/data/containerd/layer" + suffix, True),
                (title, "/usr/bin/containerd", "/var/lib/containerd-backup/layer" + suffix, True),
                (title, "/usr/bin/containerd-helper", "/var/lib/containerd/layer" + suffix, True),
                (title, "/bin/sh", "/tmp/unrelated.txt", False),
                (title, "/usr/bin/containerd", None, False),
            ]
        )
    # Exercise the OR branches as well as the representative paths above.
    cases.extend(
        [
            (RULES["cron"][0], "/bin/sh", "/etc/crontab", True),
            (RULES["shell_profile"][0], "/bin/sh", "/etc/profile.d/example.sh", True),
            (RULES["shell_profile"][0], "/bin/sh", "/etc/profile", True),
            (
                RULES["systemd"][0],
                "/bin/sh",
                "/home/user/.config/systemd/user/example.service",
                True,
            ),
            (RULES["systemd"][0], "/bin/sh", "/etc/systemd/system/example.txt", False),
            (
                RULES["cron"][0],
                "/usr/bin/containerd",
                "/var/lib/containerd/layer/etc/crontab",
                False,
            ),
            (
                RULES["shell_profile"][0],
                "/usr/bin/containerd",
                "/var/lib/containerd/layer/etc/profile.d/example.sh",
                False,
            ),
            (
                RULES["shell_profile"][0],
                "/usr/bin/containerd",
                "/var/lib/containerd/layer/etc/profile",
                False,
            ),
        ]
    )
    events = []
    expected = set()
    timestamp = "2026-10-02T08:00:00Z"
    for index, (title, image, path, alert) in enumerate(cases, 1):
        fields = {"ProcessId": str(index)}
        if image is not None:
            fields["Image"] = image
        if path is not None:
            fields["TargetFilename"] = path
        events.append(
            {
                "event_time": timestamp,
                "ingest_seq": index,
                "platform": "linux",
                "provider": "ebpf",
                "category": "File",
                "event_id": 11,
                "opcode": 1,
                "fields": fields,
            }
        )
        if alert:
            expected.add((index, title))

    with tempfile.TemporaryDirectory(prefix="rustinel-persistence-replay-") as directory:
        root = Path(directory)
        rules = root / "sigma"
        rules.mkdir()
        for name in RULES:
            source = repo / "rules/sigma/linux" / f"file_event_lnx_{name}_persistence.yml"
            shutil.copyfile(source, rules / source.name)
        payload = root / "cases.ndjson"
        data = "".join(json.dumps(event) + "\n" for event in events).encode()
        payload.write_bytes(data)
        payload.with_suffix(".manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "payload": payload.name,
                    "rustinel_version": engine_version,
                    "platform": "linux",
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
            timeout=30,
        )
        alerts = [json.loads(line) for line in output.read_text().splitlines()]
        actual = {(alert["process.pid"], alert["rule.name"]) for alert in alerts}
        if actual != expected or len(alerts) != len(expected):
            raise RuntimeError(
                f"Missing alerts: {expected - actual}; unexpected alerts: {actual - expected}"
            )
        print(f"Passed {len(cases)} persistence replay cases ({len(expected)} expected alerts).")


if __name__ == "__main__":
    main()
