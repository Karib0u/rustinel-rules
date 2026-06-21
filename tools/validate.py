#!/usr/bin/env python3
"""Detection-as-Code validation for rustinel-rules.

Mandatory v1 checks:
  - valid YAML / valid Sigma structure / YARA compiles (yara-x) / valid IOC set
  - required artifact metadata
  - unique artifact ids (across Sigma, YARA and IOC sets)
  - source/license metadata
  - ATT&CK tags when relevant
  - Rustinel telemetry compatibility
  - IOC value sanity (hash/ip/domain/regex well-formed)
  - pack manifest validation (schema + referential integrity)
  - pack attack_coverage drift guard (declared vs. derived)

Exit code 0 = all checks pass, 1 = one or more failures.

Run: uv run python tools/validate.py
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

import lib

# Telemetry channels Rustinel supports.
#
# Mirrors the engine's authoritative is_supported_category() in
# src/engine/logsource.rs (ETW on Windows, eBPF on Linux), plus "file_scan"
# for YARA / IOC executable hashing on process-start. The registry_*, file_*,
# ps_script, wmi_event, service_creation and task_creation families are
# Windows-only; rules using them must set logsource product: windows.
SUPPORTED_TELEMETRY = {
    "process_creation",
    "network_connection",
    "file_event",
    "file_create",
    "file_delete",
    "file_change",
    "file_rename",
    "registry_event",
    "registry_add",
    "registry_set",
    "registry_delete",
    "dns_query",
    "image_load",
    "ps_script",
    "wmi_event",
    "service_creation",
    "task_creation",
    "file_scan",
}

REQUIRED_SIGMA_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "references",
    "author",
    "level",
    "tags",
    "logsource",
    "detection",
]

ATTACK_TAG_PREFIX = "attack."

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_RE = re.compile(r"^(\*\.|\.)?([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}$")
VALID_HASH_LENGTHS = {32, 40, 64}  # MD5, SHA1, SHA256


class Report:
    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, where: str, msg: str):
        self.errors.append(f"[ERROR] {where}: {msg}")

    def warn(self, where: str, msg: str):
        self.warnings.append(f"[WARN]  {where}: {msg}")

    def ok(self) -> bool:
        return not self.errors


def load_yara_compiler():
    """Return a callable(raw, where, rep) that compiles a YARA rule with yara-x,
    or None if yara-x is unavailable. A compile failure is a hard error — this is
    the real load/compile gate the engine uses (Rustinel embeds yara-x)."""
    try:
        import yara_x
    except Exception:
        return None

    def _compile(raw, where, rep):
        try:
            yara_x.compile(raw)
        except Exception as exc:
            rep.error(where, f"yara-x compile failed: {exc}")

    return _compile


def load_schema_validator(schema_path: Path):
    """Return a callable(doc, where, rep) for the given schema, or None if
    jsonschema is unavailable."""
    try:
        import jsonschema
    except Exception:
        return None
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)

    def _validate(doc, where, rep):
        payload = {k: v for k, v in doc.items() if not k.startswith("__")}
        for err in validator.iter_errors(payload):
            loc = "/".join(str(p) for p in err.path) or "(root)"
            rep.error(where, f"schema: {loc}: {err.message}")

    return _validate


def check_unique_ids(artifacts, rep: Report):
    seen: dict[str, str] = {}
    for art in artifacts:
        if not art.id:
            rep.error(art.rel_path, "artifact is missing an 'id'")
            continue
        if art.id in seen:
            rep.error(art.rel_path, f"duplicate id '{art.id}' (also in {seen[art.id]})")
        else:
            seen[art.id] = art.rel_path


def check_sigma_rule(art, rep: Report):
    doc = art.meta
    if not isinstance(doc, dict):
        rep.error(art.rel_path, "Sigma rule is not a mapping")
        return

    for field in REQUIRED_SIGMA_FIELDS:
        if field not in doc or doc[field] in (None, "", [], {}):
            rep.error(art.rel_path, f"missing required field '{field}'")

    tags = doc.get("tags") or []
    if not any(str(t).startswith(ATTACK_TAG_PREFIX) for t in tags):
        rep.error(art.rel_path, "no ATT&CK tag present (expected at least one 'attack.*' tag)")

    rustinel = doc.get("rustinel") or {}
    telemetry = rustinel.get("telemetry") or []
    if not telemetry:
        rep.error(art.rel_path, "missing rustinel.telemetry (Rustinel compatibility)")
    for channel in telemetry:
        if channel not in SUPPORTED_TELEMETRY:
            rep.error(art.rel_path, f"unsupported Rustinel telemetry channel '{channel}'")

    if "expected_false_positive_level" not in rustinel:
        rep.warn(art.rel_path, "missing rustinel.expected_false_positive_level")


def check_yara_rule(art, rep: Report, compile_yara=None):
    raw = art.raw
    if not art.id:
        rep.error(art.rel_path, "YARA rule missing meta id / rule name")
    if "attack" not in raw and "reference" not in raw:
        rep.warn(art.rel_path, "no attack/reference metadata")
    if compile_yara is not None:
        # Real compile gate (yara-x) supersedes the structural brace/condition checks.
        compile_yara(raw, art.rel_path, rep)
    else:
        if raw.count("{") != raw.count("}"):
            rep.error(art.rel_path, "unbalanced braces in YARA rule")
        if "condition:" not in raw:
            rep.error(art.rel_path, "YARA rule has no 'condition:' section")


def _check_ioc_value(ioc_type: str, value: str, where: str, rep: Report):
    if ";" in value:
        rep.error(where, f"IOC value contains ';' (the file delimiter): '{value}'")
        return
    if ioc_type == "hashes":
        if not (_HEX_RE.match(value) and len(value) in VALID_HASH_LENGTHS):
            rep.error(where, f"invalid hash (expected hex MD5/SHA1/SHA256): '{value}'")
    elif ioc_type == "ips":
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            rep.error(where, f"invalid IP/CIDR: '{value}'")
    elif ioc_type == "domains":
        if not _DOMAIN_RE.match(value):
            rep.error(where, f"invalid domain: '{value}'")
    elif ioc_type == "paths_regex":
        try:
            re.compile(value)
        except re.error as exc:
            rep.error(where, f"invalid path regex '{value}': {exc}")


def check_ioc_set(art, rep: Report, schema_validate):
    doc = art.meta
    where = art.rel_path
    if not isinstance(doc, dict):
        rep.error(where, "IOC set is not a mapping")
        return

    if schema_validate is not None:
        schema_validate(doc, where, rep)

    indicators = lib.parse_ioc_indicators(doc)
    total = sum(len(v) for v in indicators.values())
    if total == 0:
        rep.error(where, "IOC set has no indicators")
    for ioc_type, entries in indicators.items():
        for value, _comment in entries:
            _check_ioc_value(ioc_type, value, where, rep)

    if not doc.get("references"):
        rep.warn(where, "no 'references' on IOC set")


REQUIRED_PACK_FIELDS = [
    "name",
    "id",
    "description",
    "os",
    "level",
    "pack_schema_version",
    "requires_rustinel",
    "default",
    "status",
    "extends",
]


def check_packs(packs, artifacts, rep: Report):
    schema_validate = load_schema_validator(lib.PACK_SCHEMA_PATH)
    if schema_validate is None:
        rep.warn("schema", "jsonschema not installed; using minimal field checks only")

    by_id = {p["id"]: p for p in packs if "id" in p}
    artifact_index = {a.id: a for a in artifacts if a.id}

    for pack in packs:
        where = str(Path(pack["__path__"]).relative_to(lib.REPO_ROOT))

        # Minimal required-field check (works without jsonschema).
        for field in REQUIRED_PACK_FIELDS:
            if field not in pack:
                rep.error(where, f"missing required field '{field}'")
        if pack.get("pack_schema_version") != 2:
            rep.error(where, "pack_schema_version must be 2 for v2")
        if not pack.get("license"):
            rep.warn(where, "no 'license' field on pack")

        if schema_validate is not None:
            schema_validate(pack, where, rep)

        # Referential integrity: rules and extends must resolve.
        rules_dict = pack.get("rules") or {}
        rule_ids_to_check = []
        if isinstance(rules_dict, list):
            rule_ids_to_check = rules_dict
        elif isinstance(rules_dict, dict):
            for key in ("has", "includes", "excludes"):
                sub = rules_dict.get(key) or {}
                if isinstance(sub, dict):
                    for cat in ("sigma", "yara", "ioc"):
                        rule_ids_to_check.extend(sub.get(cat) or [])
                elif isinstance(sub, list):
                    rule_ids_to_check.extend(sub)

        for rule_id in rule_ids_to_check:
            if rule_id not in artifact_index:
                rep.error(where, f"references unknown artifact id '{rule_id}'")
        try:
            resolved = lib.resolve_pack_rules(pack, by_id)
            if not resolved:
                rep.warn(where, "pack resolves to zero artifacts")
        except ValueError as exc:
            rep.error(where, str(exc))
            continue

        # Drift guard: declared attack_coverage should be backed by member content.
        declared = {str(t).upper() for t in pack.get("attack_coverage") or []}
        derived: set = set()
        for rule_id in resolved:
            art = artifact_index.get(rule_id)
            if art is not None:
                derived |= lib.artifact_attack_techniques(art)
        for technique in sorted(declared - derived):
            rep.warn(where, f"attack_coverage '{technique}' not found in any member artifact")


def main() -> int:
    rep = Report()

    artifacts = lib.load_all_artifacts()
    ioc_schema_validate = load_schema_validator(lib.IOC_SCHEMA_PATH)
    compile_yara = load_yara_compiler()
    if compile_yara is None:
        rep.warn("yara", "yara-x not installed; using structural YARA checks only")

    check_unique_ids(artifacts, rep)
    for art in artifacts:
        if art.kind == "sigma":
            check_sigma_rule(art, rep)
        elif art.kind == "yara":
            check_yara_rule(art, rep, compile_yara)
        elif art.kind == "ioc":
            check_ioc_set(art, rep, ioc_schema_validate)

    packs = lib.load_packs()
    check_packs(packs, artifacts, rep)

    counts = {k: sum(1 for a in artifacts if a.kind == k) for k in ("sigma", "yara", "ioc")}
    print(
        f"Checked {len(artifacts)} artifacts "
        f"({counts['sigma']} sigma, {counts['yara']} yara, {counts['ioc']} ioc) "
        f"and {len(packs)} packs."
    )
    for line in rep.warnings:
        print(line)
    for line in rep.errors:
        print(line)

    if rep.ok():
        print(f"\nOK — validation passed ({len(rep.warnings)} warning(s)).")
        return 0
    print(f"\nFAILED — {len(rep.errors)} error(s), {len(rep.warnings)} warning(s).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
