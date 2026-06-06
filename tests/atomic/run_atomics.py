#!/usr/bin/env python3
"""Atomic firing tests for rustinel-rules.

Verifies, on real Windows + Linux, that each rule actually fires: it performs a
small safe atomic action (the behaviour the rule is meant to catch) and checks
the rustinel engine wrote a matching alert.

What it does, in one privileged pass:

  1. Picks a built pack from <dist-dir>/index.json and copies it next to the
     rustinel engine binary.
  2. Writes a config.toml that points the engine's Sigma / YARA / IOC paths at
     that pack and its alert output at <engine-dir>/logs/alerts.json.<date>.
  3. Starts `rustinel run` (must be privileged: Linux eBPF -> root,
     Windows ETW -> admin).
  4. Runs each atomic action for this platform. A test "fires" when a new alert
     appears whose join key matches the rule:
        - sigma / yara : alert "rule.name" == the rule's title (looked up by id)
        - ioc / custom : an explicit {"field","contains"} match in the manifest
  5. Stops the engine and writes report-<platform>.json (+ a GitHub step
     summary). Exit code is non-zero if any gating test failed to fire, or 2 if
     the engine never started.

Pure standard library so it runs under plain `sudo python3` with no venv.
Building the pack (uv + pyyaml) happens in a separate, unprivileged step.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# This file lives at <rules-repo>/tests/atomic/run_atomics.py
HARNESS_ROOT = Path(__file__).resolve().parent          # tests/atomic
RULES_ROOT = Path(__file__).resolve().parents[2]        # the rustinel-rules repo root
ATOMICS_DIR = HARNESS_ROOT / "atomics"

ID_RE = re.compile(r"^id:\s*(.+?)\s*$", re.MULTILINE)
TITLE_RE = re.compile(r"^title:\s*(.+?)\s*$", re.MULTILINE)
TEST_STATUS_RE = re.compile(r"^\s*test_status:\s*([A-Za-z_]+)\s*$", re.MULTILINE)
TEST_REASON_RE = re.compile(r"^\s*test_reason:\s*(.+?)\s*$", re.MULTILINE)
YARA_RULE_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)")
YARA_META_ID_RE = re.compile(r'\bid\s*=\s*"([^"]+)"')
YARA_TEST_STATUS_RE = re.compile(r'\btest_status\s*=\s*"([^"]+)"')
YARA_TEST_REASON_RE = re.compile(r'\btest_reason\s*=\s*"([^"]+)"')


# --------------------------------------------------------------------------- #
# Discovery: rules, packs                                                      #
# --------------------------------------------------------------------------- #
def detect_platform() -> str:
    s = sys.platform
    if s.startswith("linux"):
        return "linux"
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "macos"
    return s


def _clean_scalar(value: str) -> str:
    return value.strip().strip("'\"")


def _extract_yaml_list(text: str, field: str) -> list[str]:
    match = re.search(rf"^{field}:\s*$", text, re.MULTILINE)
    if not match:
        return []
    out: list[str] = []
    for line in text[match.end():].splitlines():
        if not line.strip():
            continue
        if not line.startswith("  "):
            break
        item = line.strip()
        if item.startswith("- "):
            item = item[2:].split("#", 1)[0].strip()
            if item:
                out.append(_clean_scalar(item))
    return out


def _extract_yaml_scalar(text: str, field: str) -> str | None:
    match = re.search(rf"^{field}:\s*(.+?)\s*$", text, re.MULTILINE)
    if not match:
        return None
    return _clean_scalar(match.group(1).split("#", 1)[0])


def index_rules(rules_dir: Path) -> dict[str, dict]:
    """Map artifact id to title, status, reason and path by scanning sources.

    Deliberately a line scan (not a YAML parse) so the runner stays
    dependency-free; the firing runner has to work under plain sudo python.
    """
    out: dict[str, dict] = {}
    root = rules_dir / "rules"
    if not root.is_dir():
        return out

    for path in (root / "sigma").rglob("*.yml"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        m_id = ID_RE.search(text)
        if not m_id:
            continue
        rid = _clean_scalar(m_id.group(1))
        m_title = TITLE_RE.search(text)
        m_status = TEST_STATUS_RE.search(text)
        m_reason = TEST_REASON_RE.search(text)
        out[rid] = {
            "title": _clean_scalar(m_title.group(1)) if m_title else None,
            "test_status": m_status.group(1).lower() if m_status else None,
            "test_reason": _clean_scalar(m_reason.group(1)) if m_reason else None,
            "file": str(path.relative_to(rules_dir)),
        }

    for path in (root / "yara").rglob("*.yar"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        m_name = YARA_RULE_RE.search(text)
        m_id = YARA_META_ID_RE.search(text)
        if not m_id and not m_name:
            continue
        rid = (m_id.group(1) if m_id else m_name.group(1)).strip()
        m_status = YARA_TEST_STATUS_RE.search(text)
        m_reason = YARA_TEST_REASON_RE.search(text)
        out[rid] = {
            "title": m_name.group(1) if m_name else rid,
            "test_status": m_status.group(1).lower() if m_status else None,
            "test_reason": m_reason.group(1).strip() if m_reason else None,
            "file": str(path.relative_to(rules_dir)),
        }

    for path in (root / "ioc").rglob("*.yml"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        m_id = ID_RE.search(text)
        if not m_id:
            continue
        rid = _clean_scalar(m_id.group(1))
        m_status = TEST_STATUS_RE.search(text)
        m_reason = TEST_REASON_RE.search(text)
        out[rid] = {
            "title": rid,
            "test_status": m_status.group(1).lower() if m_status else None,
            "test_reason": _clean_scalar(m_reason.group(1)) if m_reason else None,
            "file": str(path.relative_to(rules_dir)),
        }
    return out


def load_source_packs(rules_dir: Path) -> dict[str, dict]:
    packs: dict[str, dict] = {}
    for path in (rules_dir / "packs").rglob("pack.yml"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        pack_id = _extract_yaml_scalar(text, "id")
        if not pack_id:
            continue
        packs[pack_id] = {
            "id": pack_id,
            "os": _extract_yaml_scalar(text, "os"),
            "level": _extract_yaml_scalar(text, "level"),
            "extends": _extract_yaml_list(text, "extends"),
            "rules": _extract_yaml_list(text, "rules"),
            "file": str(path.relative_to(rules_dir)),
        }
    return packs


def resolve_source_pack_rules(pack_id: str, packs: dict[str, dict]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def visit(current: str, stack: list[str]):
        if current in stack:
            raise SystemExit(f"Pack extends cycle: {' -> '.join(stack + [current])}")
        pack = packs.get(current)
        if not pack:
            raise SystemExit(f"Unknown pack in extends: {current}")
        for parent in pack.get("extends", []):
            visit(parent, stack + [current])
        for rule_id in pack.get("rules", []):
            if rule_id not in seen:
                seen.add(rule_id)
                ordered.append(rule_id)

    visit(pack_id, [])
    return ordered


def pick_pack(dist_dir: Path, os_name: str, requested: str) -> dict:
    index = json.loads((dist_dir / "index.json").read_text(encoding="utf-8"))
    packs = [p for p in index["packs"] if p["os"] == os_name]
    if not packs:
        sys.exit(f"No packs for os={os_name} in {dist_dir / 'index.json'}")
    if requested != "auto":
        for p in packs:
            if p["id"] == requested:
                return p
        sys.exit(f"Pack '{requested}' not found for os={os_name}")
    # auto: the most inclusive (highest rule_count) pack - packs are cumulative.
    return max(packs, key=lambda p: p.get("rule_count", 0))


# --------------------------------------------------------------------------- #
# Engine setup + lifecycle                                                     #
# --------------------------------------------------------------------------- #
def setup_engine(engine_dir: Path, dist_dir: Path, pack: dict) -> Path:
    pack_id = pack["id"]
    src = dist_dir / pack_id
    dst = engine_dir / pack_id
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)

    config = f"""# Generated by run_atomics.py - points the engine at pack '{pack_id}'.
[scanner]
sigma_enabled = true
sigma_rules_path = "{pack_id}/rules/sigma"
yara_enabled = true
yara_rules_path = "{pack_id}/rules/yara"

[ioc]
enabled = true
hashes_path = "{pack_id}/rules/ioc/hashes.txt"
ips_path = "{pack_id}/rules/ioc/ips.txt"
domains_path = "{pack_id}/rules/ioc/domains.txt"
paths_regex_path = "{pack_id}/rules/ioc/paths_regex.txt"

[logging]
level = "info"
directory = "logs"
filename = "rustinel.log"
console_output = false

[alerts]
directory = "logs"
filename = "alerts.json"

[reload]
enabled = false
"""
    (engine_dir / "config.toml").write_text(config, encoding="utf-8")
    logs = engine_dir / "logs"
    logs.mkdir(exist_ok=True)
    return logs


def resolve_binary(engine_dir: Path, os_name: str, override: Path | None) -> Path:
    """Locate the rustinel binary. Either installed into --engine-dir, or built
    from source elsewhere and passed via --engine-bin (e.g. target/release)."""
    name = "rustinel.exe" if os_name == "windows" else "rustinel"
    binary = override.resolve() if override else (engine_dir / name)
    if not binary.exists():
        sys.exit(f"Engine binary not found: {binary}\n"
                 f"  Install a release into --engine-dir, or build the sibling "
                 f"rustinel repo and pass --engine-bin <path>.")
    if os_name != "windows":
        os.chmod(binary, 0o755)
    return binary


def start_engine(binary: Path, engine_dir: Path, stdout_log: Path):
    fh = open(stdout_log, "wb")
    proc = subprocess.Popen(
        [str(binary), "run", "--no-console"],
        cwd=str(engine_dir),
        stdout=fh,
        stderr=subprocess.STDOUT,
    )
    return proc, fh


# --------------------------------------------------------------------------- #
# Alert reading                                                                #
# --------------------------------------------------------------------------- #
def snapshot_alerts(logs_dir: Path) -> dict[str, int]:
    return {str(p): p.stat().st_size for p in logs_dir.glob("alerts.json*")}


def read_new_alerts(logs_dir: Path, snapshot: dict[str, int]) -> list[dict]:
    alerts: list[dict] = []
    for p in sorted(logs_dir.glob("alerts.json*")):
        offset = snapshot.get(str(p), 0)
        try:
            with open(p, "rb") as fh:
                fh.seek(offset)
                data = fh.read()
        except OSError:
            continue
        for line in data.decode("utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # partial trailing line; picked up next poll
    return alerts


# --------------------------------------------------------------------------- #
# Test selection + matching                                                    #
# --------------------------------------------------------------------------- #
def load_manifest(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["tests"]


def select_tests(tests: list[dict], os_name: str, flt: str | None) -> list[dict]:
    out = [t for t in tests if t["platform"] == os_name]
    if flt:
        out = [t for t in out if flt in t["name"] or flt in t["id"]]
    return out


def make_predicate(test: dict, rules: dict[str, dict]):
    """Return (predicate, human_description). predicate(alert_dict) -> bool."""
    exp = test.get("expect")
    if exp:
        field = exp["field"]
        if "equals" in exp:
            target, mode = exp["equals"], "equals"
        else:
            target, mode = exp["contains"], "contains"

        def pred(alert):
            v = alert.get(field)
            return isinstance(v, str) and (v == target if mode == "equals" else target in v)

        sign = "==" if mode == "equals" else "~"
        return pred, f'{field} {sign} "{target}"'

    title = rules.get(test["id"], {}).get("title")
    if not title:
        return None, f"(no title found for id {test['id']})"

    def pred(alert):
        return alert.get("rule.name") == title

    return pred, f'rule.name == "{title}"'


def run_script(script: Path, os_name: str, timeout: int):
    if os_name == "windows":
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
    else:
        cmd = ["bash", str(script)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return None, "atomic script timed out"


# --------------------------------------------------------------------------- #
# Coverage report (no engine needed)                                          #
# --------------------------------------------------------------------------- #
def coverage(
    tests: list[dict],
    rules: dict[str, dict],
    packs: dict[str, dict],
    strict_essential: bool,
) -> int:
    manifest_keys = {(t["platform"], t["id"]) for t in tests}
    manifest_ids = {t["id"] for t in tests}
    known_ids = set(rules)
    platforms_by_rule: dict[str, set[str]] = {}
    essential_ids: set[tuple[str, str]] = set()

    for pack in packs.values():
        os_name = pack.get("os")
        if os_name == "macos":
            continue
        for rule_id in resolve_source_pack_rules(pack["id"], packs):
            platforms_by_rule.setdefault(rule_id, set()).add(os_name)
            if pack.get("level") == "essential":
                essential_ids.add((os_name, rule_id))

    expected_atomic: set[tuple[str, str]] = set()
    for rule_id, rule in rules.items():
        if rule.get("test_status") != "atomic":
            continue
        platforms = platforms_by_rule.get(rule_id)
        if platforms:
            expected_atomic.update((platform, rule_id) for platform in platforms)
        elif rule_id in manifest_ids:
            expected_atomic.update(key for key in manifest_keys if key[1] == rule_id)

    missing_atomic = sorted(expected_atomic - manifest_keys)
    unknown = sorted(key for key in manifest_keys if key[1] not in known_ids)
    untracked = sorted(
        key for key in manifest_keys
        if key[1] in known_ids and rules[key[1]].get("test_status") != "atomic"
    )
    essential_none = sorted(
        key for key in essential_ids
        if rules.get(key[1], {}).get("test_status") in (None, "none")
    )
    manual_without_reason = sorted(
        key for key in essential_ids
        if rules.get(key[1], {}).get("test_status") == "manual"
        and not rules.get(key[1], {}).get("test_reason")
    )

    print("Coverage (per platform manifest entries vs artifact test_status):\n")
    for platform, rule_id in missing_atomic:
        print(f"  MISSING test   {platform:<7} {rule_id}  {rules[rule_id].get('title')}")
    for platform, rule_id in untracked:
        status = rules[rule_id].get("test_status")
        print(f"  has test, status={status!r:9} {platform:<7} {rule_id}  {rules[rule_id].get('title')}")
    for platform, rule_id in unknown:
        print(f"  UNKNOWN id     {platform:<7} {rule_id}  (in manifest, not in rules repo)")

    if essential_none:
        print("\nEssential rules still marked none:")
        for platform, rule_id in essential_none:
            rule = rules.get(rule_id, {})
            print(f"  {platform:<7} {rule_id}  {rule.get('title')}  ({rule.get('file')})")

    if manual_without_reason:
        print("\nEssential manual rules missing test_reason:")
        for platform, rule_id in manual_without_reason:
            rule = rules.get(rule_id, {})
            print(f"  {platform:<7} {rule_id}  {rule.get('title')}  ({rule.get('file')})")

    print(
        f"\n  {len(tests)} tests in manifest, {len(manifest_keys)} platform/id pairs, "
        f"{len(expected_atomic)} expected atomic pairs, {len(missing_atomic)} missing, "
        f"{len(unknown)} unknown."
    )
    if strict_essential:
        return 1 if (missing_atomic or unknown or essential_none or manual_without_reason) else 0
    return 1 if (missing_atomic or unknown) else 0


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="Run rustinel-rules atomic firing tests.")
    ap.add_argument("--platform", default=detect_platform(),
                    choices=["linux", "windows", "macos"])
    ap.add_argument("--engine-dir", type=Path, default=HARNESS_ROOT / ".engine",
                    help="staging dir for config.toml + pack + logs (and the binary if installed there)")
    ap.add_argument("--engine-bin", type=Path, default=None,
                    help="path to the rustinel binary if built from source (e.g. ../rustinel/target/release/rustinel)")
    ap.add_argument("--rules-dir", type=Path, default=RULES_ROOT,
                    help="rustinel-rules repo root (default: this repo)")
    ap.add_argument("--dist-dir", type=Path, default=None,
                    help="built packs dir (default: <rules-dir>/dist)")
    ap.add_argument("--pack", default="auto", help="pack id, or 'auto' for the most inclusive")
    ap.add_argument("--manifest", type=Path, default=HARNESS_ROOT / "manifest.json")
    ap.add_argument("--filter", default=None, help="substring of test name or rule id")
    ap.add_argument("--timeout", type=int, default=30, help="seconds to wait for an alert")
    ap.add_argument("--retry-interval", type=int, default=6,
                    help="seconds between re-running the atomic action while waiting")
    ap.add_argument("--warmup", type=int, default=10, help="seconds to let the engine start")
    ap.add_argument("--script-timeout", type=int, default=30)
    ap.add_argument("--list", action="store_true", help="list selected tests and exit")
    ap.add_argument("--check-coverage", action="store_true",
                    help="compare manifest with rules' test_status and exit")
    ap.add_argument("--strict-essential", action="store_true",
                    help="with --check-coverage, fail on Essential none/manual-without-reason")
    ap.add_argument("--keep-running", action="store_true", help="leave the engine running")
    args = ap.parse_args()

    os_name = args.platform
    dist_dir = args.dist_dir or (args.rules_dir / "dist")
    rules = index_rules(args.rules_dir)
    tests = select_tests(load_manifest(args.manifest), os_name, args.filter)

    if args.check_coverage:
        packs = load_source_packs(args.rules_dir)
        return coverage(load_manifest(args.manifest), rules, packs, args.strict_essential)

    if not tests:
        print(f"No tests selected for platform={os_name} filter={args.filter!r}")
        return 0

    if args.list:
        for t in tests:
            _, desc = make_predicate(t, rules)
            tag = " [allow_failure]" if t.get("allow_failure") else ""
            print(f"  {t['name']:<28} {t['engine']:<6} -> {desc}{tag}")
        return 0

    # ---- real run: needs the engine + a built pack ----
    engine_dir = args.engine_dir.resolve()
    engine_dir.mkdir(parents=True, exist_ok=True)
    pack = pick_pack(dist_dir, os_name, args.pack)
    print(f"== rustinel atomic firing tests ({os_name}) ==")
    print(f"   pack:   {pack['id']} ({pack.get('rule_count', '?')} rules)")
    print(f"   engine: {engine_dir}")
    logs_dir = setup_engine(engine_dir, dist_dir, pack)
    binary = resolve_binary(engine_dir, os_name, args.engine_bin)

    stdout_log = engine_dir / "engine.stdout.log"
    proc, fh = start_engine(binary, engine_dir, stdout_log)
    print(f"   warming up {args.warmup}s ...")
    time.sleep(args.warmup)
    if proc.poll() is not None:
        fh.close()
        print("\nENGINE FAILED TO START - last output:\n")
        print(stdout_log.read_text(encoding="utf-8", errors="ignore")[-3000:])
        print("\nLikely cause: insufficient privilege for eBPF/ETW, or kernel "
              "doesn't support the probes on this runner.")
        return 2

    results = []
    try:
        for t in tests:
            pred, desc = make_predicate(t, rules)
            script = ATOMICS_DIR / t["script"]
            if pred is None:
                results.append({**t, "status": "ERROR", "expect": desc})
                print(f"  [ERROR] {t['name']}: {desc}")
                continue

            # Re-run the action periodically until detected or timeout. This
            # survives the ETW/eBPF startup race (the first action can fire before
            # telemetry is fully live) and transient flakiness; a genuinely
            # undetected rule still fails once the timeout elapses.
            snap = snapshot_alerts(logs_dir)
            found, rc, out = None, None, ""
            deadline = time.time() + args.timeout
            next_action = 0.0
            while time.time() < deadline and not found:
                if time.time() >= next_action:
                    rc, out = run_script(script, os_name, args.script_timeout)
                    next_action = time.time() + args.retry_interval
                for alert in read_new_alerts(logs_dir, snap):
                    if pred(alert):
                        found = alert
                        break
                if not found:
                    time.sleep(0.5)

            status = "PASS" if found else ("FAIL (allowed)" if t.get("allow_failure") else "FAIL")
            results.append({
                "id": t["id"], "name": t["name"], "engine": t["engine"],
                "expect": desc, "status": status, "action_exit": rc,
                "allow_failure": bool(t.get("allow_failure")),
                "action_output": out.strip()[-500:] if not found else "",
            })
            mark = "PASS" if found else "FAIL"
            print(f"  [{mark}] {t['name']:<28} ({desc})")
    finally:
        if not args.keep_running:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        fh.close()

    return report(results, os_name)


def report(results: list[dict], os_name: str) -> int:
    passed = [r for r in results if r["status"] == "PASS"]
    gating_fail = [r for r in results if r["status"] in ("FAIL", "ERROR")]
    out_path = HARNESS_ROOT / f"report-{os_name}.json"
    out_path.write_text(json.dumps({"platform": os_name, "results": results}, indent=2),
                        encoding="utf-8")

    print(f"\n== summary ({os_name}): {len(passed)}/{len(results)} fired ==")
    for r in results:
        if r["status"] != "PASS":
            print(f"   {r['status']:<14} {r['name']}  (expected {r['expect']})")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        lines = [f"### Atomic firing tests - {os_name}", "",
                 "| Rule | Engine | Result |", "|---|---|---|"]
        emoji = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "FAIL (allowed)": "⚠️ FAIL (allowed)",
                 "ERROR": "🛑 ERROR"}
        for r in results:
            lines.append(f"| {r['name']} | {r['engine']} | {emoji.get(r['status'], r['status'])} |")
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    print(f"   report: {out_path}")
    return 1 if gating_fail else 0


if __name__ == "__main__":
    sys.exit(main())
