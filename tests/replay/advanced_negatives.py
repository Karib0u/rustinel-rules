"""Replay the documented negative examples of every Advanced Sigma rule (#44).

Each Advanced rule lists `rustinel.negatives`: benign events (an installer, a
package manager, an administrator's read-only command) that must stay silent.
They sit next to `rustinel.tuning`, which names the fields an operator filters
on. This replays every negative against its own rule with the real engine, so a
loosened pattern fails here instead of in a customer's alert queue.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
import lib  # noqa: E402

PROVIDER = {"linux": "ebpf", "macos": "esf", "windows": "etw"}

# Sigma logsource category or service -> (replay category, event id).
EVENT_SHAPE = {
    "process_creation": ("Process", 1),
    "file_event": ("File", 11),
    "file_delete": ("File", 23),
    "file_rename": ("File", 71),
    "network_connection": ("Network", 3),
    "registry_set": ("Registry", 13),
    "ps_script": ("Scripting", 4104),
    "service_creation": ("Service", 7045),
    "image_load": ("ImageLoad", 7),
    "security": ("Security", 4698),
}


# Registry value-set events carry action code 39 in the opcode.
OPCODE = {"Registry": 39}


def advanced_sigma_rules():
    return lib.advanced_sigma_rules(lib.load_packs(), lib.load_all_artifacts())


def event_shape(artifact):
    logsource = artifact.meta["logsource"]
    return EVENT_SHAPE[logsource.get("category") or logsource.get("service")]


def build_events(artifact, negatives):
    platform = artifact.meta["logsource"]["product"]
    category, event_id = event_shape(artifact)
    timestamp = "2026-10-08T08:00:00Z"
    events = []
    for index, negative in enumerate(negatives, 1):
        fields = {"ProcessId": str(index), **negative["fields"]}
        record_id = event_id
        if category == "Security":
            fields.setdefault("EventID", str(event_id))
            record_id = int(fields["EventID"])
        events.append(
            {
                "event_time": timestamp,
                "ingest_seq": index,
                "platform": platform,
                "provider": PROVIDER[platform],
                "category": category,
                "event_id": record_id,
                "opcode": OPCODE.get(category, 1),
                "fields": fields,
            }
        )
    return events


def replay(engine, artifact, events):
    platform = artifact.meta["logsource"]["product"]
    timestamp = "2026-10-08T08:00:00Z"
    with tempfile.TemporaryDirectory(prefix="rustinel-advanced-negatives-") as directory:
        root = Path(directory)
        rules = root / "sigma"
        rules.mkdir()
        shutil.copyfile(artifact.path, rules / artifact.path.name)
        payload = root / "cases.ndjson"
        data = "".join(json.dumps(event) + "\n" for event in events).encode()
        payload.write_bytes(data)
        version = json.loads((REPO / "compatibility/engine.json").read_text())["version"]
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
            [str(engine), "replay", str(payload), "--config", str(config), "--output", str(output)],
            check=True,
            timeout=60,
            capture_output=True,
        )
        return [json.loads(line) for line in output.read_text().splitlines()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--platform", choices=sorted(PROVIDER), help="only this platform")
    args = parser.parse_args()
    engine = args.engine.resolve()
    failures = []
    rules = cases = 0
    for artifact in advanced_sigma_rules():
        platform = artifact.meta["logsource"]["product"]
        if args.platform and platform != args.platform:
            continue
        negatives = (artifact.meta.get("rustinel") or {}).get("negatives") or []
        if not negatives:
            failures.append(f"{artifact.path.name}: no rustinel.negatives")
            continue
        alerts = replay(engine, artifact, build_events(artifact, negatives))
        title = artifact.meta["title"]
        fired = sorted(int(a["process.pid"]) for a in alerts if a["rule.name"] == title)
        for index in fired:
            failures.append(
                f"{title}: benign example {index} alerted: {negatives[index - 1]['reason']}"
            )
        rules += 1
        cases += len(negatives)
    if failures:
        raise RuntimeError("\n".join(failures))
    print(f"Passed {cases} negative examples across {rules} Advanced rules.")


if __name__ == "__main__":
    main()
