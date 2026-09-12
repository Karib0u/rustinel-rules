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
  - no production rule selects on a field the engine never populates
  - each pack's requires_rustinel covers what its own content needs
  - preview / test-only content is registered, and no pack references it

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
# for YARA / IOC executable hashing on process-start. The registry_*, image_load,
# ps_script, wmi_event, service_creation and task_creation families are
# Windows-only; rules using them must set logsource product: windows. The file_*
# family is collected on all three platforms, but only Windows emits file_change,
# and only Linux/macOS populate SourceFilename on a rename (see
# NEVER_POPULATED_FIELDS).
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

# Fields the certified engine never populates, keyed by (product, category).
#
# Mirrors the `never` rows of the engine field-availability contract
# (rustinel/compatibility/field-availability.json). A selection on one of these
# is dead weight at best: the field is missing on every event, so the selection
# can never be true. When it is the only selection, the rule can never fire at
# all — which is how the Essential scheduled-task rule (TaskContent) and the
# unsigned-DLL hunting rule (Signed) shipped without ever producing an alert.
#
# Such a rule belongs under preview/ with a `telemetry-blocked` entry naming the
# engine issue, not in a pack. Add a row here whenever the contract marks a field
# `never`; drop it when the engine starts populating it.
NEVER_POPULATED_FIELDS: dict[tuple[str, str], set[str]] = {
    # TaskScheduler event 106 carries no task XML; needs Security 4698.
    ("windows", "task_creation"): {"TaskContent"},
    # Kernel-Process image-load records carry no Authenticode result.
    ("windows", "image_load"): {"Signed", "Signature"},
    # No token/logon resolution on the ETW process path yet.
    ("windows", "process_creation"): {"User", "ParentUser", "LogonId", "LogonGuid"},
    # Kernel-File gives no pre-rename name, and no creation timestamps.
    ("windows", "file_event"): {
        "SourceFilename",
        "CreationUtcTime",
        "PreviousCreationUtcTime",
    },
    # macOS network comes from /dev/bpf: no direction, user or reverse name.
    ("macos", "network_connection"): {"Initiated", "User", "DestinationHostname"},
    # macOS DNS is captured at the packet layer, unattributed to a process.
    ("macos", "dns_query"): {"Image", "ProcessId"},
    ("macos", "process_creation"): {"ParentCommandLine"},
    # Linux DNS parses the query only, not the answer.
    ("linux", "dns_query"): {"QueryResults", "QueryStatus"},
}

# The file_* sub-categories share one field contract.
FILE_CATEGORY_ALIASES = {
    "file_create",
    "file_delete",
    "file_rename",
    "file_change",
}
DNS_CATEGORY_ALIASES = {"dns"}


def _contract_category(category: str) -> str:
    if category in FILE_CATEGORY_ALIASES:
        return "file_event"
    if category in DNS_CATEGORY_ALIASES:
        return "dns_query"
    return category


def _detection_fields(detection: dict) -> set[str]:
    """Every field name a rule's selections reference, modifiers stripped."""
    fields: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                fields.add(str(key).split("|", 1)[0])
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for name, selection in (detection or {}).items():
        if name in ("condition", "timeframe"):
            continue
        walk(selection)
    return fields


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


def check_engine_field_availability(art, rep: Report):
    """Reject a production rule that selects on a field the engine never populates."""
    doc = art.meta
    if not isinstance(doc, dict):
        return
    logsource = doc.get("logsource") or {}
    product = str(logsource.get("product") or "").lower()
    category = _contract_category(str(logsource.get("category") or "").lower())
    blocked = NEVER_POPULATED_FIELDS.get((product, category))
    if not blocked:
        return
    used = _detection_fields(doc.get("detection") or {})
    for field in sorted(blocked & used):
        rep.error(
            art.rel_path,
            f"selects on '{field}', which Rustinel never populates for "
            f"{product}/{logsource.get('category')} — the rule cannot match. "
            f"Move it to preview/ with a telemetry-blocked entry, or drop the field.",
        )


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


def check_packs(packs, artifacts, rep: Report, preview_by_id=None):
    schema_validate = load_schema_validator(lib.PACK_SCHEMA_PATH)
    if schema_validate is None:
        rep.warn("schema", "jsonschema not installed; using minimal field checks only")

    by_id = {p["id"]: p for p in packs if "id" in p}
    artifact_index = {a.id: a for a in artifacts if a.id}
    preview_by_id = preview_by_id or {}

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
            if rule_id in artifact_index:
                continue
            entry = preview_by_id.get(rule_id)
            if entry:
                rep.error(
                    where,
                    f"references '{rule_id}', which is {entry.get('state')} content under "
                    f"preview/{entry.get('path')}. Production packs may not ship preview or "
                    f"test-only artifacts.",
                )
            else:
                rep.error(where, f"references unknown artifact id '{rule_id}'")
        try:
            resolved = lib.resolve_pack_rules(pack, by_id)
            if not resolved:
                rep.warn(where, "pack resolves to zero artifacts")
        except ValueError as exc:
            rep.error(where, str(exc))
            continue

        # A pack that under-claims its engine requirement is worse than one that
        # does not declare it: `rustinel doctor` reports the pack as compatible
        # with an engine that cannot populate the fields its rules select on, so
        # the rules load and silently never match.
        declared_floor = lib.constraint_floor(pack.get("requires_rustinel"))
        derived, drivers = lib.pack_min_engine(resolved, artifact_index, pack.get("os"))
        if declared_floor is None:
            rep.warn(
                where,
                f"requires_rustinel {pack.get('requires_rustinel')!r} is not a '>=X.Y.Z' "
                f"constraint, so its floor cannot be checked (content needs >={derived})",
            )
        elif lib.parse_version(declared_floor) < lib.parse_version(derived):
            why = "; ".join(
                f"{artifact_index[rule_id].meta.get('title', rule_id)} ({reasons[0]})"
                for rule_id, reasons in list(drivers.items())[:2]
            )
            rep.error(
                where,
                f"requires_rustinel is >={declared_floor} but the pack's content needs "
                f">={derived} — {why}",
            )

        # Drift guard: declared attack_coverage should be backed by member content.
        declared = {str(t).upper() for t in pack.get("attack_coverage") or []}
        derived: set = set()
        for rule_id in resolved:
            art = artifact_index.get(rule_id)
            if art is not None:
                derived |= lib.artifact_attack_techniques(art)
        for technique in sorted(declared - derived):
            rep.warn(where, f"attack_coverage '{technique}' not found in any member artifact")


def check_preview(preview_artifacts, rep: Report, ioc_schema_validate, compile_yara):
    """The preview tree is validated like production content, plus its register.

    Preview rules must still parse and carry full metadata so promotion is a move
    rather than a rewrite; they are exempt only from the never-populated-field
    check, which is the very reason most of them are here.
    """
    register = lib.load_preview_register()
    schema_validate = load_schema_validator(lib.PREVIEW_SCHEMA_PATH)
    where_register = lib.PREVIEW_REGISTER_PATH.relative_to(lib.REPO_ROOT).as_posix()

    if schema_validate is not None and register:
        schema_validate(register, where_register, rep)

    entries = register.get("entries") or []
    by_id = {str(e.get("id")): e for e in entries if e.get("id")}

    for art in preview_artifacts:
        if art.kind == "sigma":
            check_sigma_rule(art, rep)
        elif art.kind == "yara":
            check_yara_rule(art, rep, compile_yara)
        elif art.kind == "ioc":
            check_ioc_set(art, rep, ioc_schema_validate)
        if art.id and art.id not in by_id:
            rep.error(
                art.rel_path,
                f"not listed in {where_register}; every preview artifact needs an entry "
                f"declaring its state, reason and blocker",
            )

    # Registered paths are written POSIX-style; compare on that spelling so the
    # check behaves the same on a Windows checkout.
    known_paths = {a.path.relative_to(lib.PREVIEW_DIR).as_posix() for a in preview_artifacts}
    for entry in entries:
        path = str(entry.get("path") or "").replace("\\", "/")
        if path not in known_paths:
            rep.error(
                where_register,
                f"entry '{entry.get('id')}' points at preview/{path}, which does not exist",
            )

    return by_id


def main() -> int:
    rep = Report()

    artifacts = lib.load_all_artifacts()
    ioc_schema_validate = load_schema_validator(lib.IOC_SCHEMA_PATH)
    compile_yara = load_yara_compiler()
    if compile_yara is None:
        rep.warn("yara", "yara-x not installed; using structural YARA checks only")

    preview_artifacts = lib.load_preview_artifacts()

    check_unique_ids(artifacts + preview_artifacts, rep)
    for art in artifacts:
        if art.kind == "sigma":
            check_sigma_rule(art, rep)
            check_engine_field_availability(art, rep)
        elif art.kind == "yara":
            check_yara_rule(art, rep, compile_yara)
        elif art.kind == "ioc":
            check_ioc_set(art, rep, ioc_schema_validate)

    preview_by_id = check_preview(preview_artifacts, rep, ioc_schema_validate, compile_yara)

    packs = lib.load_packs()
    check_packs(packs, artifacts, rep, preview_by_id)

    counts = {k: sum(1 for a in artifacts if a.kind == k) for k in ("sigma", "yara", "ioc")}
    print(
        f"Checked {len(artifacts)} artifacts "
        f"({counts['sigma']} sigma, {counts['yara']} yara, {counts['ioc']} ioc) "
        f"and {len(packs)} packs, "
        f"plus {len(preview_artifacts)} non-production artifact(s) under preview/."
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
