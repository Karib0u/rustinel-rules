"""Exercise the shipped mining-pool IOC feed with offline DNS events."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TIMESTAMP = "2026-11-27T08:00:00Z"
POOL = "xmr-eu1.nanopool.org"
CASES = (
    (POOL, True),
    (POOL.upper(), True),
    ("nanopool.org", False),
    ("help.nanopool.org", False),
    (f"sub.{POOL}", False),
    (f"{POOL}.example.invalid", False),
)


def check_pack(engine: Path, version: str, platform: str, provider: str, event_id: int):
    pack = REPO / "dist" / f"{platform}-advanced"
    domains = pack / "ioc/domains.txt"
    if not domains.is_file():
        raise FileNotFoundError(f"{domains} is missing. Run tools/build_packs.py first.")
    with tempfile.TemporaryDirectory(prefix="rustinel-ioc-replay-") as directory:
        root = Path(directory)
        payload = root / "dns.ndjson"
        events = [
            {
                "event_time": TIMESTAMP,
                "ingest_seq": pid,
                "platform": platform,
                "provider": provider,
                "category": "Dns",
                "event_id": event_id,
                "opcode": 1,
                "fields": {"ProcessId": str(pid), "QueryName": host},
            }
            for pid, (host, _) in enumerate(CASES, 1)
        ]
        data = "".join(json.dumps(event) + "\n" for event in events).encode()
        payload.write_bytes(data)
        payload.with_suffix(".manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "payload": payload.name,
                    "rustinel_version": version,
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
        sigma = root / "sigma"
        sigma.mkdir()
        config = root / "config.toml"
        config.write_text(
            f"[scanner]\nsigma_rules_path = {json.dumps(str(sigma))}\nyara_enabled = false\n"
            "[ioc]\nenabled = true\n"
            + "".join(
                f"{kind}_path = {json.dumps(str(pack / 'ioc' / (kind + '.txt')))}\n"
                for kind in ("hashes", "ips", "domains", "paths_regex")
            )
            + "\n[dedup]\nenabled = false\n"
            + f"[logging]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
            + f"[alerts]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
        )
        output = root / "alerts.ndjson"
        subprocess.run(
            [str(engine), "replay", str(payload), "--config", str(config), "--output", str(output)],
            check=True,
            timeout=30,
        )
        alerts = [json.loads(line) for line in output.read_text().splitlines()]
        actual = [(alert["process.pid"], alert["rule.name"]) for alert in alerts]
        expected = [(pid, f"ioc:domain:{POOL}") for pid, (_, fires) in enumerate(CASES, 1) if fires]
        if actual != expected or any(
            "[ioc-cryptomining-pools]" not in alert.get("rule.description", "") for alert in alerts
        ):
            raise RuntimeError(f"{pack.name}: expected {expected}, got {alerts}")
    print(f"Passed {len(CASES)} DNS IOC replay cases for {pack.name}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    version = json.loads((REPO / "compatibility/engine.json").read_text())["version"]
    reported = subprocess.check_output([str(engine), "--version"], text=True).strip()
    if reported != f"rustinel {version}":
        raise RuntimeError(f"Expected certified rustinel {version}, got {reported}")
    for platform, provider, event_id in (
        ("windows", "etw", 3008),
        ("linux", "ebpf", 22),
        ("macos", "bpf", 22),
    ):
        check_pack(engine, version, platform, provider, event_id)


if __name__ == "__main__":
    main()
