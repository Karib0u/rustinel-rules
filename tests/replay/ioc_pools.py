"""Exercise the shipped mining-pool and LOLRMM IOC feeds with offline DNS events."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TIMESTAMP = "2026-11-27T08:00:00Z"
DNS_SOURCES = {"windows": ("etw", 3008), "linux": ("ebpf", 22), "macos": ("bpf", 22)}
POOL = "xmr-eu1.nanopool.org"
POOL_CASES = (
    (POOL, POOL),
    (POOL.upper(), POOL),
    ("nanopool.org", None),
    ("help.nanopool.org", None),
    (f"sub.{POOL}", None),
    (f"{POOL}.example.invalid", None),
)
SCREENCONNECT_RELAY = "instance-g01s1n-relay.screenconnect.com"
SPLASHTOP_RELAY = "relay.splashtop.com"
LOLRMM_CASES = (
    ("boot.net.anydesk.com", ".net.anydesk.com"),
    ("RELAY-TEST.NET.ANYDESK.COM", ".net.anydesk.com"),
    (SCREENCONNECT_RELAY.upper() + ".", SCREENCONNECT_RELAY),
    ("agent-api.atera.com", "agent-api.atera.com"),
    (SPLASHTOP_RELAY, f".{SPLASHTOP_RELAY}"),
    (f"test.{SPLASHTOP_RELAY}.", f".{SPLASHTOP_RELAY}"),
    ("rs-ny.rustdesk.com", "rs-ny.rustdesk.com"),
    ("meshcentral.com", "meshcentral.com"),
    ("telesupportgroup.com", "telesupportgroup.com"),
    ("icanhazip.tacticalrmm.io", "icanhazip.tacticalrmm.io"),
    ("router15.teamviewer.com", "router15.teamviewer.com"),
    ("tenant.rmmservice.eu", ".rmmservice.eu"),
    ("syncro-live.syncromsp.com", "syncro-live.syncromsp.com"),
    ("remote.eu.action1.com", "remote.eu.action1.com"),
    ("anydesk.com", None),
    ("support.anydesk.com", None),
    ("relay-test.notnet.anydesk.com", None),
    (f"x{SPLASHTOP_RELAY}", None),
    (f"node.{SPLASHTOP_RELAY}.example.invalid", None),
    (f"sub.{SCREENCONNECT_RELAY}", None),
    ("cloud.screenconnect.com", None),
    ("docs.tacticalrmm.com", None),
    ("icanhazip.com", None),
    ("login.tailscale.com", None),
    ("support.teamviewer.com", None),
    ("d123.cloudfront.net", None),
    ("app.azurewebsites.net", None),
    ("a1-backend-packages.s3.amazonaws.com", None),
)


def check_pack(engine, version, pack_id, set_id, cases):
    pack = REPO / "dist" / pack_id
    platform = pack_id.split("-", 1)[0]
    provider, event_id = DNS_SOURCES[platform]
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
            for pid, (host, _) in enumerate(cases, 1)
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
        expected = [
            (pid, f"ioc:domain:{indicator}")
            for pid, (_, indicator) in enumerate(cases, 1)
            if indicator is not None
        ]
        if actual != expected or any(
            f"[{set_id}]" not in alert.get("rule.description", "") for alert in alerts
        ):
            raise RuntimeError(f"{pack.name}: expected {expected}, got {alerts}")
    print(f"Passed {len(cases)} DNS IOC replay cases for {set_id} in {pack.name}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    version = json.loads((REPO / "compatibility/engine.json").read_text())["version"]
    reported = subprocess.check_output([str(engine), "--version"], text=True).strip()
    if reported != f"rustinel {version}":
        raise RuntimeError(f"Expected certified rustinel {version}, got {reported}")
    for platform in DNS_SOURCES:
        check_pack(
            engine,
            version,
            f"{platform}-advanced",
            "ioc-cryptomining-pools",
            POOL_CASES,
        )
        if platform != "macos":
            check_pack(
                engine,
                version,
                f"{platform}-hunting",
                "ioc-lolrmm-relay-domains",
                LOLRMM_CASES,
            )


if __name__ == "__main__":
    main()
