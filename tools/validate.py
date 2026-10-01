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
  - on a tagged build, the tag agrees with the declared release version

Exit code 0 = all checks pass, 1 = one or more failures.

Run: uv run python tools/validate.py
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from pathlib import Path

import engine_contract
import lib

# Telemetry channels Rustinel supports.
#
# Mirrors the engine's authoritative is_supported_category() in
# src/engine/logsource.rs (ETW on Windows, eBPF on Linux), plus "file_scan"
# for YARA / IOC executable hashing on process-start. The registry_*, image_load,
# ps_script, ps_module, wmi_event, service_creation and task_creation families
# are Windows-only; rules using them must set logsource product: windows.
# "security" is the Windows Security event log, selected in Sigma with
# `product: windows, service: security` and no category. The file_*
# family is collected on all three platforms, but only Windows emits file_change,
# and only Linux/macOS populate SourceFilename on a rename (see
# the vendored engine field contract).
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
    "ps_module",
    "security",
    "wmi_event",
    "service_creation",
    "task_creation",
    "file_scan",
}

# Categories routed by native event ID, where an EventID the engine does not
# collect can never match. Sysmon-style categories are left out: the engine
# maps their Sysmon event IDs onto its own sources (DNS EventID 22 still
# matches the DNS Client's 3006/3008).
EVENT_ID_ROUTED_CATEGORIES = {"security"}


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

# A correlation document replaces `logsource` + `detection` with `correlation`.
REQUIRED_CORRELATION_FIELDS = [
    f for f in REQUIRED_SIGMA_FIELDS if f not in ("logsource", "detection")
] + ["correlation"]

# What rsigma-parser 0.21 (the engine's Sigma parser) accepts.
CORRELATION_TYPES = {
    "event_count",
    "value_count",
    "temporal",
    "temporal_ordered",
    "value_sum",
    "value_avg",
    "value_percentile",
    "value_median",
}
TEMPORAL_CORRELATION_TYPES = {"temporal", "temporal_ordered"}
VALUE_CORRELATION_TYPES = {
    "value_count",
    "value_sum",
    "value_avg",
    "value_percentile",
    "value_median",
}
CORRELATION_OPERATORS = {"lt", "lte", "gt", "gte", "eq", "neq"}
_TIMESPAN_RE = re.compile(r"^\d+[smhdwMy]$")

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
    or None if yara-x is unavailable. A compile failure is a hard error - this is
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

    required = REQUIRED_CORRELATION_FIELDS if lib.is_correlation(doc) else REQUIRED_SIGMA_FIELDS
    for field in required:
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


def check_correlation(
    art, rep: Report, sigma_by_id: dict, never_populated: engine_contract.BlockedFields
):
    """Check a correlation document against the engine parser and its references."""
    doc = art.meta
    if not lib.is_correlation(doc):
        return
    where = art.rel_path
    corr = doc["correlation"]

    ctype = corr.get("type")
    if ctype not in CORRELATION_TYPES:
        rep.error(where, f"correlation type {ctype!r} is not one of {sorted(CORRELATION_TYPES)}")

    timespan = corr.get("timespan", corr.get("timeframe"))
    if not isinstance(timespan, str) or not _TIMESPAN_RE.match(timespan):
        rep.error(where, f"correlation timespan {timespan!r} must look like 30s, 5m, 1h or 7d")

    condition = corr.get("condition")
    if ctype in TEMPORAL_CORRELATION_TYPES and (condition is None or isinstance(condition, str)):
        # Omitted means every referenced rule must match: the Sigma default, which
        # Rustinel restores at load time since v1.5.0. A string is an extended
        # condition over rule names, e.g. "rule_a and rule_b".
        pass
    elif not isinstance(condition, dict) or not CORRELATION_OPERATORS & condition.keys():
        rep.error(where, "correlation condition needs an operator (gte, gt, lte, lt, eq, neq)")
    elif ctype in VALUE_CORRELATION_TYPES and not condition.get("field"):
        rep.error(where, f"a {ctype} correlation condition needs a 'field'")

    group_by = corr.get("group-by") or []
    if not isinstance(group_by, list) or not all(isinstance(f, str) for f in group_by):
        rep.error(where, "correlation group-by must be a list of field names")
        group_by = []

    rule_ids = lib.correlation_rule_ids(doc)
    if not rule_ids:
        rep.error(where, "correlation rules must list at least one rule id")
    referenced = []
    for rule_id in rule_ids:
        target = sigma_by_id.get(rule_id)
        if target is None:
            rep.error(where, f"correlation references unknown Sigma rule id '{rule_id}'")
        elif lib.is_correlation(target.meta):
            rep.error(where, f"correlation references another correlation '{rule_id}'")
        else:
            referenced.append(target)

    products = {str((t.meta.get("logsource") or {}).get("product") or "") for t in referenced}
    if len(products) > 1:
        rep.error(where, f"correlation mixes rules for {sorted(products)}; use one platform")

    telemetry = set((doc.get("rustinel") or {}).get("telemetry") or [])
    for target in referenced:
        logsource = target.meta.get("logsource") or {}
        missing = set((target.meta.get("rustinel") or {}).get("telemetry") or []) - telemetry
        if missing:
            rep.error(
                where,
                f"rustinel.telemetry lacks {sorted(missing)} needed by referenced rule "
                f"'{target.id}'",
            )
        product = str(logsource.get("product") or "").lower()
        blocked = never_populated.get((product, lib.contract_category(logsource)), {})
        for field in group_by:
            if field in blocked or "*" in blocked:
                rep.error(
                    where,
                    f"groups by '{field}', which Rustinel never populates for the referenced "
                    f"rule '{target.id}' ({product}/{lib.logsource_category(logsource)})",
                )


def check_engine_field_availability(
    art, rep: Report, never_populated: engine_contract.BlockedFields
):
    """Reject a production rule that selects on a field the engine never populates."""
    doc = art.meta
    if not isinstance(doc, dict):
        return
    logsource = doc.get("logsource") or {}
    product = str(logsource.get("product") or "").lower()
    category = lib.contract_category(logsource)
    blocked = never_populated.get((product, category))
    if not blocked:
        return
    used = _detection_fields(doc.get("detection") or {})
    for field in sorted(used if "*" in blocked else blocked.keys() & used):
        reason = "; ".join(blocked.get(field, blocked.get("*", ())))
        rep.error(
            art.rel_path,
            f"selects on '{field}', which Rustinel never populates for "
            f"{product}/{lib.logsource_category(logsource)}: {reason}. "
            f"Move it to preview/ with a telemetry-blocked entry, or drop the field.",
        )


def _selected_event_ids(detection: dict) -> set[str]:
    """Literal EventID values a rule selects on, as strings. Values behind a
    modifier (|gt, |re, ...) are not literal IDs and are skipped."""
    ids: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key) == "EventID":
                    for item in value if isinstance(value, list) else [value]:
                        if isinstance(item, (int, str)) and not isinstance(item, bool):
                            ids.add(str(item).strip())
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for name, selection in (detection or {}).items():
        if name in ("condition", "timeframe"):
            continue
        walk(selection)
    return ids


def check_collected_event_ids(art, rep: Report, collected: engine_contract.EventIds):
    """Reject a rule that selects an event ID its channel never collects."""
    doc = art.meta
    if not isinstance(doc, dict):
        return
    logsource = doc.get("logsource") or {}
    product = str(logsource.get("product") or "").lower()
    category = lib.contract_category(logsource)
    if category not in EVENT_ID_ROUTED_CATEGORIES:
        return
    known = collected.get((product, category), set())
    for event_id in sorted(_selected_event_ids(doc.get("detection") or {}) - known):
        rep.error(
            art.rel_path,
            f"selects EventID {event_id}, which Rustinel does not collect on "
            f"{product}/{category} (collected: {', '.join(sorted(known, key=int)) or 'none'}).",
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
            # Name the members that actually set the derived floor, with the
            # reason that reaches it, not just the first members with a reason.
            setters = []
            for rule_id, reasons in drivers.items():
                floor, _ = lib.artifact_min_engine(artifact_index[rule_id])
                if floor == derived:
                    reason = next((r for r in reasons if derived in r), reasons[-1])
                    setters.append(
                        f"{artifact_index[rule_id].meta.get('title', rule_id)} ({reason})"
                    )
            why = "; ".join(setters[:2]) or "the platform baseline"
            rep.error(
                where,
                f"requires_rustinel is >={declared_floor} but the pack's content needs "
                f">={derived} - {why}",
            )

        # A correlation only fires if every rule it references loads with it.
        members = set(resolved)
        for rule_id in resolved:
            artifact = artifact_index.get(rule_id)
            if artifact is None or not lib.is_correlation(artifact.meta):
                continue
            for ref in lib.correlation_rule_ids(artifact.meta):
                if ref not in members:
                    rep.error(
                        where,
                        f"correlation '{rule_id}' references '{ref}', which is not in this pack",
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


def check_release_version(rep: Report):
    """On a tag build, the tag and the declared release version must agree.

    Without this the mismatch only shows up as archives named after the wrong
    release, after they have been published. GitHub Actions sets
    GITHUB_REF_TYPE/GITHUB_REF_NAME; off a tag there is nothing to compare and
    the check is a no-op.
    """
    version = lib.release_version()
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        return
    tag = (os.environ.get("GITHUB_REF_NAME") or "").strip()
    if tag.lstrip("v") != version:
        rep.error(
            "pyproject.toml",
            f"building tag {tag!r} but [project].version is {version!r} - bump the "
            f"version in the release PR before tagging, or retag",
        )


def main() -> int:
    rep = Report()

    try:
        engine_pin, never_populated = engine_contract.load_contract()
        collected_event_ids = engine_contract.load_event_ids()
    except (OSError, ValueError) as exc:
        print(f"[ERROR] engine field contract: {exc}")
        return 1
    print(
        f"Engine field contract: Rustinel {engine_pin['version']} "
        f"at {engine_pin['revision']} (schema {engine_pin['schema_version']})."
    )

    artifacts = lib.load_all_artifacts()
    ioc_schema_validate = load_schema_validator(lib.IOC_SCHEMA_PATH)
    compile_yara = load_yara_compiler()
    if compile_yara is None:
        rep.warn("yara", "yara-x not installed; using structural YARA checks only")

    preview_artifacts = lib.load_preview_artifacts()

    check_unique_ids(artifacts + preview_artifacts, rep)
    sigma_by_id = {a.id: a for a in artifacts if a.kind == "sigma" and a.id}
    for art in artifacts:
        if art.kind == "sigma":
            check_sigma_rule(art, rep)
            check_engine_field_availability(art, rep, never_populated)
            check_collected_event_ids(art, rep, collected_event_ids)
            check_correlation(art, rep, sigma_by_id, never_populated)
        elif art.kind == "yara":
            check_yara_rule(art, rep, compile_yara)
        elif art.kind == "ioc":
            check_ioc_set(art, rep, ioc_schema_validate)

    preview_by_id = check_preview(preview_artifacts, rep, ioc_schema_validate, compile_yara)
    check_release_version(rep)

    packs = lib.load_packs()
    check_packs(packs, artifacts, rep, preview_by_id)

    counts = {k: sum(1 for a in artifacts if a.kind == k) for k in ("sigma", "yara", "ioc")}
    print(
        f"Checked {len(artifacts)} artifacts "
        f"({counts['sigma']} sigma, {counts['yara']} yara, {counts['ioc']} ioc) "
        f"and {len(packs)} packs, "
        f"plus {len(preview_artifacts)} non-production artifact(s) under preview/. "
        f"Release version {lib.release_version()}."
    )
    for line in rep.warnings:
        print(line)
    for line in rep.errors:
        print(line)

    if rep.ok():
        print(f"\nOK - validation passed ({len(rep.warnings)} warning(s)).")
        return 0
    print(f"\nFAILED - {len(rep.errors)} error(s), {len(rep.warnings)} warning(s).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
