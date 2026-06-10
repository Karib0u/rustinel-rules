#!/usr/bin/env python3
"""Emit a rich, front-end-friendly catalog of all detection content.

Where ``build_packs.py`` produces engine-ready *pack* artifacts (what Rustinel
loads), this tool produces a single ``dist/catalog.json`` describing every
canonical detection in full, enough for a website to render one indexable page
per rule, per ATT&CK technique and per pack, with zero YAML/YARA parsing on the
consumer side.

It is the **contract** between this repo and the Rustinel website
(rustinel-front-final): the site syncs this file and renders from it.

Shape (``rustinel-rules/catalog@1``):

    {
      "schema", "generated_at", "release_version", "source_repo",
      "counts":     { rules, sigma, yara, ioc, packs, techniques },
      "rules":      [ <full per-rule record, see rule_record()> ],
      "techniques": [ { id, slug, name, tactic, url, rule_ids, rule_count } ],
      "packs":      [ { id, name, os, level, ..., rule_ids, engine } ]
    }

Run: uv run python tools/build_catalog.py [--version X.Y.Z]
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime

import lib

DEFAULT_VERSION = "0.2.0"
SOURCE_REPO = "https://github.com/Karib0u/rustinel-rules"
GITHUB_BLOB = f"{SOURCE_REPO}/blob/main"
ATTACK_MAP_PATH = lib.REPO_ROOT / "tools" / "attack_techniques.json"

# Reserved single-segment slugs the website routes statically under /rules/.
# A rule must never slugify to one of these, or its detail page would collide.
RESERVED_SLUGS = {"attack", "packs", "windows", "linux", "macos", "index"}

# Words that should keep a specific casing when humanizing a YARA/IOC title from
# its id (which has no `title` field). Everything else is title-cased.
_TITLE_CASING = {
    "eicar": "EICAR",
    "xmrig": "XMRig",
    "lsass": "LSASS",
    "ntds": "NTDS",
    "ssh": "SSH",
    "uac": "UAC",
    "wmi": "WMI",
    "ioc": "IOC",
    "url": "URL",
    "macos": "macOS",
}
# Prefixes carried by artifact ids/rule-names that add no meaning to a title.
_TITLE_DROP = {"yara", "ioc", "win", "windows", "lnx", "linux", "mac", "osx", "susp", "hunting"}

_TACTIC_TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TACTIC_NAME_RE = re.compile(r"^attack\.([a-z][a-z0-9-]+)$", re.IGNORECASE)
_YARA_META_RE = re.compile(r"meta:\s*(.*?)\n\s*(?:strings|condition)\s*:", re.DOTALL)
_YARA_KV_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"', re.MULTILINE)


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return re.sub(r"-{2,}", "-", slug)


def humanize_from_id(raw: str) -> str:
    parts = [p for p in re.split(r"[-_]+", str(raw)) if p and p.lower() not in _TITLE_DROP]
    return " ".join(_TITLE_CASING.get(p.lower(), p.capitalize()) for p in parts) or str(raw)


def technique_url(tid: str) -> str:
    base, _, sub = tid.partition(".")
    path = f"{base}/{sub}" if sub else base
    return f"https://attack.mitre.org/techniques/{path}/"


def load_attack_map() -> dict[str, dict]:
    data = json.loads(ATTACK_MAP_PATH.read_text(encoding="utf-8"))
    return data.get("techniques", {})


def parse_yara_meta(raw: str) -> dict[str, str]:
    block = _YARA_META_RE.search(raw)
    if not block:
        return {}
    return {k: v for k, v in _YARA_KV_RE.findall(block.group(1))}


def as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()] if str(value).strip() else []


def rule_record(art: lib.Artifact, pack_ids: list[str], attack_map: dict) -> dict:
    """Build the full, self-contained record for a single detection artifact."""
    techniques = sorted(lib.artifact_attack_techniques(art))
    tactics: set[str] = set()

    if art.kind == "sigma":
        meta = art.meta
        title = str(meta.get("title") or "").strip()
        description = " ".join(str(meta.get("description") or "").split())
        level = str(meta.get("level") or "").strip().lower() or None
        status = str(meta.get("status") or "").strip().lower() or None
        logsource = meta.get("logsource") or {}
        product = str(logsource.get("product") or "").strip().lower() or None
        category = str(logsource.get("category") or "").strip().lower() or None
        references = as_list(meta.get("references"))
        falsepositives = as_list(meta.get("falsepositives"))
        author = str(meta.get("author") or "").strip() or None
        date = str(meta.get("date") or "").strip() or None
        rustinel = meta.get("rustinel") or {}
        telemetry = as_list(rustinel.get("telemetry"))
        efp = str(rustinel.get("expected_false_positive_level") or "").strip().lower() or None
        test_status = str(rustinel.get("test_status") or "").strip().lower() or None
        os_name = product or "windows"
        for tag in as_list(meta.get("tags")):
            tactic_match = _TACTIC_NAME_RE.match(tag)
            if tactic_match and not _TACTIC_TECH_RE.match(tag):
                tactics.add(tactic_match.group(1).lower())
        source_lang = "yaml"

    elif art.kind == "yara":
        meta = parse_yara_meta(art.raw)
        title = (meta.get("title") or "").strip() or humanize_from_id(
            art.meta.get("rule_name") or art.id
        )
        description = " ".join((meta.get("description") or "").split())
        level = (meta.get("level") or "").strip().lower() or None
        status = (meta.get("status") or "").strip().lower() or None
        product = (meta.get("os") or "").strip().lower() or None
        category = "file_scan"
        references = [r for r in [meta.get("reference"), meta.get("references")] if r]
        falsepositives = []
        author = (meta.get("author") or "").strip() or None
        date = (meta.get("date") or "").strip() or None
        telemetry = as_list(meta.get("telemetry") or "file_scan")
        efp = (meta.get("expected_false_positive_level") or "").strip().lower() or None
        test_status = (meta.get("test_status") or "").strip().lower() or None
        os_name = product or "windows"
        source_lang = "yara"

    else:  # ioc
        meta = art.meta
        title = (meta.get("title") or meta.get("name") or "").strip() or humanize_from_id(art.id)
        description = " ".join(str(meta.get("description") or "").split())
        level = str(meta.get("severity") or "").strip().lower() or None
        status = str(meta.get("status") or "").strip().lower() or None
        os_list = as_list(meta.get("os")) or ["common"]
        product = os_list[0].lower()
        category = "ioc"
        references = as_list(meta.get("references"))
        falsepositives = []
        author = str(meta.get("author") or "").strip() or None
        date = str(meta.get("date") or "").strip() or None
        telemetry = ["file_scan"]
        efp = None
        test_status = None
        os_name = product
        source_lang = "yaml"

    # Backfill tactics from each technique's curated primary tactic so YARA/IOC
    # (which have no tactic tags) and any gaps still group correctly.
    for tid in techniques:
        info = attack_map.get(tid)
        if info and info.get("tactic"):
            tactics.add(info["tactic"])

    slug = slugify(title) or slugify(art.id)
    if slug in RESERVED_SLUGS:
        slug = f"{slug}-{art.kind}"

    return {
        "id": art.id,
        "slug": slug,
        "kind": art.kind,
        "title": title,
        "description": description,
        "level": level,
        "status": status,
        "os": os_name,
        "product": product,
        "category": category,
        "tactics": sorted(tactics),
        "techniques": techniques,
        "references": references,
        "falsepositives": falsepositives,
        "telemetry": telemetry,
        "expected_false_positive_level": efp,
        "test_status": test_status,
        "author": author,
        "date": date,
        "packs": pack_ids,
        "source": art.raw,
        "source_lang": source_lang,
        "github_url": f"{GITHUB_BLOB}/{art.rel_path}",
    }


def build_catalog(version: str) -> dict:
    attack_map = load_attack_map()
    artifacts = [a for a in lib.load_all_artifacts() if a.id]
    packs = lib.load_packs()
    by_id = {p["id"]: p for p in packs if "id" in p}

    # Resolve cumulative pack membership: rule id -> [pack ids] and pack records.
    rule_packs: dict[str, list[str]] = {}
    pack_entries: list[dict] = []
    for pack in packs:
        pack_id = pack["id"]
        resolved = lib.resolve_pack_rules(pack, by_id)
        for rid in resolved:
            rule_packs.setdefault(rid, []).append(pack_id)
        pack_entries.append(
            {
                "id": pack_id,
                "name": pack.get("name"),
                "slug": pack_id,
                "os": pack.get("os"),
                "level": pack.get("level"),
                "description": pack.get("description"),
                "default": bool(pack.get("default", False)),
                "status": pack.get("status"),
                "requires_rustinel": pack.get("requires_rustinel"),
                "expected_false_positive_level": pack.get("expected_false_positive_level"),
                "extends": as_list(pack.get("extends")),
                "attack_coverage": as_list(pack.get("attack_coverage")),
                "telemetry_requirements": as_list(pack.get("telemetry_requirements")),
                "rule_ids": resolved,
                "rule_count": len(resolved),
                "artifact": f"{pack_id}-{version}.zip",
                "engine": {
                    "sigma_rules_path": f"{pack_id}/rules/sigma",
                    "yara_rules_path": f"{pack_id}/rules/yara",
                    "hashes_path": f"{pack_id}/rules/ioc/hashes.txt",
                    "ips_path": f"{pack_id}/rules/ioc/ips.txt",
                    "domains_path": f"{pack_id}/rules/ioc/domains.txt",
                    "paths_regex_path": f"{pack_id}/rules/ioc/paths_regex.txt",
                },
            }
        )

    rules = [rule_record(a, rule_packs.get(a.id, []), attack_map) for a in artifacts]

    # Warn (don't fail) on any technique missing from the curated ATT&CK map so
    # the build still succeeds but a maintainer notices the gap.
    seen_techniques: dict[str, list[str]] = {}
    for r in rules:
        for tid in r["techniques"]:
            seen_techniques.setdefault(tid, []).append(r["id"])
    for tid in sorted(seen_techniques):
        if tid not in attack_map:
            print(f"[catalog] WARNING: technique {tid} missing from attack_techniques.json")

    techniques = []
    for tid in sorted(seen_techniques):
        info = attack_map.get(tid, {})
        techniques.append(
            {
                "id": tid,
                "slug": tid.lower().replace(".", "-"),
                "name": info.get("name") or tid,
                "tactic": info.get("tactic"),
                "url": technique_url(tid),
                "rule_ids": seen_techniques[tid],
                "rule_count": len(seen_techniques[tid]),
            }
        )

    by_kind = {"sigma": 0, "yara": 0, "ioc": 0}
    for r in rules:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1

    return {
        "schema": "rustinel-rules/catalog@1",
        "generated_at": datetime.now(UTC).isoformat(),
        "release_version": version,
        "source_repo": SOURCE_REPO,
        "counts": {
            "rules": len(rules),
            "sigma": by_kind["sigma"],
            "yara": by_kind["yara"],
            "ioc": by_kind["ioc"],
            "packs": len(pack_entries),
            "techniques": len(techniques),
        },
        "rules": sorted(rules, key=lambda r: r["title"].lower()),
        "techniques": techniques,
        "packs": pack_entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the rustinel-rules website catalog.")
    parser.add_argument(
        "--version", default=DEFAULT_VERSION, help="Release version (default %(default)s)"
    )
    args = parser.parse_args()

    lib.DIST_DIR.mkdir(parents=True, exist_ok=True)
    catalog = build_catalog(args.version)
    out_path = lib.DIST_DIR / "catalog.json"
    out_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")

    c = catalog["counts"]
    print(
        f"[catalog] wrote {out_path.relative_to(lib.REPO_ROOT)}: "
        f"{c['rules']} rules ({c['sigma']} sigma / {c['yara']} yara / {c['ioc']} ioc), "
        f"{c['techniques']} techniques, {c['packs']} packs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
