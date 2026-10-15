"""Check the shell-history tamper rules (Linux and macOS) with the real engine.

Regression guard for the noisy `file_event` history rule (#46, #47): an
interactive shell saves history on every exit, which the engine reports as a
write/modify on the generic `file_event` channel. The corrected rules key on
`file_delete`, on a `file_rename` whose *source* is a history file, and on the
command line of in-place destruction. Each case is one synthetic event; the
positives must still alert and the ordinary history writes must not.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

PLATFORMS = {
    "linux": {
        "provider": "ebpf",
        "home": "/home/alice",
        "shell": "/usr/bin/bash",
        "rules": {
            "delete": ("Shell History File Deleted", "file_delete_lnx_history_delete.yml"),
            "rename": (
                "Shell History File Renamed Away",
                "file_rename_lnx_history_rename_away.yml",
            ),
            "destroy": (
                "Shell History Destroyed in Place",
                "proc_creation_lnx_history_destruction.yml",
            ),
        },
    },
    "macos": {
        "provider": "esf",
        "home": "/Users/alice",
        "shell": "/bin/zsh",
        "rules": {
            "delete": (
                "Shell History File Deleted (macOS)",
                "file_delete_macos_history_delete.yml",
            ),
            "rename": (
                "Shell History File Renamed Away (macOS)",
                "file_rename_macos_history_rename_away.yml",
            ),
            "destroy": (
                "Shell History Destroyed in Place (macOS)",
                "proc_creation_macos_history_destruction.yml",
            ),
        },
    },
}


def cases(platform, home, shell):
    """(kind, event fields, rule key that must alert or None)."""
    bash_hist = f"{home}/.bash_history"
    zsh_hist = f"{home}/.zsh_history"
    return [
        # file_delete: removing a history file alerts; other deletes do not.
        ("delete", {"Image": "/usr/bin/rm", "TargetFilename": bash_hist}, "delete"),
        ("delete", {"Image": "/usr/bin/rm", "TargetFilename": zsh_hist}, "delete"),
        ("delete", {"Image": "/usr/bin/rm", "TargetFilename": f"{home}/.zsh_history.lock"}, None),
        ("delete", {"Image": "/usr/bin/rm", "TargetFilename": f"{home}/.zshrc"}, None),
        ("delete", {"Image": "/usr/bin/rm", "TargetFilename": "/tmp/history_export.txt"}, None),
        # file_rename: only a history file as the *source* alerts. zsh saves by
        # renaming a temp file onto .zsh_history on every exit; that must not.
        (
            "rename",
            {"Image": "/usr/bin/mv", "SourceFilename": bash_hist, "TargetFilename": "/tmp/x"},
            "rename",
        ),
        (
            "rename",
            {
                "Image": "/usr/bin/mv",
                "SourceFilename": zsh_hist,
                "TargetFilename": f"{home}/.zsh_history.bak",
            },
            "rename",
        ),
        (
            "rename",
            {"Image": shell, "SourceFilename": f"{zsh_hist}.new", "TargetFilename": zsh_hist},
            None,
        ),
        (
            "rename",
            {"Image": shell, "SourceFilename": f"{home}/.zhistXYZ", "TargetFilename": zsh_hist},
            None,
        ),
        (
            "rename",
            {"Image": "/usr/bin/mv", "SourceFilename": "/tmp/a", "TargetFilename": bash_hist},
            None,
        ),
        # Ordinary history writes: create/modify of the history file is not tamper.
        ("write", {"Image": shell, "TargetFilename": bash_hist}, None),
        ("write", {"Image": shell, "TargetFilename": zsh_hist}, None),
        ("write", {"Image": shell, "TargetFilename": f"{zsh_hist}.new"}, None),
        # process_creation: in-place destruction by command line.
        # macOS ships no shred, so only the Linux rule has that branch.
        (
            "process",
            {"Image": "/usr/bin/shred", "CommandLine": f"shred -u {bash_hist}"},
            "destroy" if platform == "linux" else None,
        ),
        (
            "process",
            {"Image": "/usr/bin/truncate", "CommandLine": f"truncate -s 0 {zsh_hist}"},
            "destroy",
        ),
        (
            "process",
            {"Image": "/bin/ln", "CommandLine": f"ln -sf /dev/null {bash_hist}"},
            "destroy",
        ),
        (
            "process",
            {"Image": shell, "CommandLine": f"{shell} -c 'cat /dev/null > {bash_hist}'"},
            "destroy",
        ),
        ("process", {"Image": "/usr/bin/less", "CommandLine": f"less {bash_hist}"}, None),
        ("process", {"Image": "/usr/bin/grep", "CommandLine": f"grep ssh {zsh_hist}"}, None),
        ("process", {"Image": "/usr/bin/tail", "CommandLine": f"tail -n 50 {bash_hist}"}, None),
        (
            "process",
            {"Image": "/usr/bin/truncate", "CommandLine": f"truncate -s 0 {home}/app.log"},
            None,
        ),
        (
            "process",
            {"Image": "/usr/bin/truncate", "CommandLine": f"truncate -s 1M {bash_hist}"},
            None,
        ),
        ("process", {"Image": "/usr/bin/shred", "CommandLine": f"shred -u {home}/notes.txt"}, None),
        ("process", {"Image": "/bin/ln", "CommandLine": f"ln -sf /dev/null {home}/.cache"}, None),
    ]


def build_event(index, kind, fields):
    base = {"ProcessId": str(index), **fields}
    if kind == "process":
        return {"category": "Process", "event_id": 1, "fields": base}
    event_id = {"delete": 23, "rename": 71, "write": 11}[kind]
    return {"category": "File", "event_id": event_id, "fields": base}


def replay(engine, repo, platform, spec):
    timestamp = "2026-10-08T08:00:00Z"
    events, expected = [], set()
    for index, (kind, fields, rule) in enumerate(cases(platform, spec["home"], spec["shell"]), 1):
        event = build_event(index, kind, fields)
        event.update(
            event_time=timestamp,
            ingest_seq=index,
            platform=platform,
            provider=spec["provider"],
            opcode=1,
        )
        events.append(event)
        if rule is not None:
            expected.add((index, spec["rules"][rule][0]))

    with tempfile.TemporaryDirectory(prefix=f"rustinel-{platform}-history-replay-") as directory:
        root = Path(directory)
        rules = root / "sigma"
        rules.mkdir()
        for _, name in spec["rules"].values():
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
            capture_output=True,
        )
        alerts = [json.loads(line) for line in output.read_text().splitlines()]
        actual = {(int(alert["process.pid"]), alert["rule.name"]) for alert in alerts}
        if actual != expected or len(alerts) != len(expected):
            raise RuntimeError(
                f"{platform}: missing alerts: {sorted(expected - actual)}; "
                f"unexpected alerts: {sorted(actual - expected)}"
            )
    return len(events), len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--platform", choices=sorted(PLATFORMS), action="append")
    args = parser.parse_args()
    engine = args.engine.resolve()
    repo = Path(__file__).resolve().parents[2]
    for platform in args.platform or sorted(PLATFORMS):
        total, positives = replay(engine, repo, platform, PLATFORMS[platform])
        print(
            f"Passed {total} {platform} shell-history replay cases ({positives} expected alerts)."
        )


if __name__ == "__main__":
    main()
