#!/usr/bin/env python3
"""Detection-as-Code validation for rustinel-rules.

Mandatory v1 checks:
  - valid YAML / valid Sigma structure / YARA compiles (yara-x) / valid IOC set
  - required artifact metadata
  - unique artifact ids (across Sigma, YARA and IOC sets)
  - source/license metadata
  - ATT&CK tactics, techniques and software IDs
  - Rustinel telemetry compatibility
  - IOC value sanity and shared-infrastructure warninglists
  - pack manifest validation (schema + referential integrity)
  - pack attack_coverage and test_status match what member rules derive
  - no production rule selects on a field the engine never populates
  - each pack's requires_rustinel covers what its own content needs
  - preview / test-only content is registered, and no pack references it
  - promoted Sigma rules have gating atomics, provenance, tuning and benign evidence
  - on a tagged build, the tag agrees with the declared release version

Exit code 0 = all checks pass, 1 = one or more failures.

Run: uv run python tools/validate.py
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import date
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import yaml

import engine_contract
import lib

# Telemetry channels Rustinel supports.
#
# Mirrors the engine's authoritative is_supported_category() in
# src/engine/logsource.rs (ETW on Windows, eBPF on Linux), plus "file_scan"
# for YARA / IOC executable hashing on process-start. The registry_*, image_load,
# driver_load, ps_script, ps_module, wmi_event, service_creation and task_creation
# families are Windows-only; rules using them must set logsource product: windows.
# "security" is the Windows Security event log, selected in Sigma with
# `product: windows, service: security` and no category; "windefend" (Defender
# Operational) and "application" follow the same pattern with their own
# service names. "ps_classic_start" is classic PowerShell engine start (400),
# selected by that category or by `service: powershell-classic` alone. These
# three arrived in v1.9.0. Since v1.11.0, product-less `category: antivirus`
# routes to Defender detections and `product: linux, service: auditd` uses the
# auditd view. The file_* family is collected on all three platforms, but only
# Windows emits file_change and only Linux/macOS populate SourceFilename on a
# rename (see the vendored engine field contract).
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
    "driver_load",
    "ps_script",
    "ps_module",
    "security",
    "windefend",
    "antivirus",
    "auditd",
    "application",
    "ps_classic_start",
    "wmi_event",
    "service_creation",
    "task_creation",
    "file_scan",
}

# Categories routed by native event ID, where an EventID the engine does not
# collect can never match. Sysmon-style categories are left out: the engine
# maps their Sysmon event IDs onto its own sources (DNS EventID 22 still
# matches the DNS Client's 3006/3008).
EVENT_ID_ROUTED_CATEGORIES = {
    "security",
    "windefend",
    "antivirus",
    "application",
    "ps_classic_start",
}


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

SIGMA_STATUSES = ("experimental", *lib.PROMOTED_SIGMA_STATUSES, "deprecated")
ATOMIC_DIR = lib.REPO_ROOT / "tests" / "atomic"
IOC_WARNINGLISTS_PATH = lib.REPO_ROOT / "tools" / "ioc_warninglists.json"
_UUID4_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_ISO_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
HOST_ROLES = {
    "workstation",
    "server",
    "domain_controller",
    "web_server",
    "developer",
    "container_host",
}

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

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_RE = re.compile(r"(?:\*\.|\.)?(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}\.?")
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


def _check_attack_id(ident: str, kind: str, where: str, rep: Report):
    metadata = lib.load_attack_metadata()
    if ident in metadata["deprecated"]:
        replacement = metadata["deprecated"][ident]
        rep.error(where, f"deprecated ATT&CK ID '{ident}'. Use '{replacement}' instead")
    elif ident not in metadata["software" if kind == "software" else "techniques"]:
        rep.error(where, f"unknown ATT&CK {kind} ID '{ident}' in attack_techniques.json")


def _http_source_url(value) -> bool:
    if not isinstance(value, str) or re.search(r"[\s\x00-\x1f\x7f\\]", value):
        return False
    try:
        url = urlsplit(value)
        return (
            url.scheme in ("http", "https")
            and bool(url.hostname)
            and url.username is None
            and (url.port is None or url.port > 0)
        )
    except ValueError:
        return False


def check_references(references, where: str, rep: Report):
    if (
        not isinstance(references, list)
        or not references
        or not all(map(_http_source_url, references))
    ):
        rep.error(where, "rule needs references with HTTP(S) source URLs")


def _iso_date(value) -> date | None:
    if not _ISO_DATE_RE.fullmatch(str(value)):
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def check_sigma_rule(art, rep: Report, *, production: bool = True):
    doc = art.meta
    if not isinstance(doc, dict):
        rep.error(art.rel_path, "Sigma rule is not a mapping")
        return

    required = REQUIRED_CORRELATION_FIELDS if lib.is_correlation(doc) else REQUIRED_SIGMA_FIELDS
    for field in required:
        if field not in doc or doc[field] in (None, "", [], {}):
            rep.error(art.rel_path, f"missing required field '{field}'")

    rule_id = doc.get("id")
    if not isinstance(rule_id, str) or not _UUID4_RE.fullmatch(rule_id):
        rep.error(art.rel_path, "Sigma id must be a canonical lowercase UUID v4")
    if production:
        check_references(doc.get("references"), art.rel_path, rep)

    created = _iso_date(doc.get("date"))
    modified = _iso_date(doc.get("modified"))
    for field, parsed in (("date", created), ("modified", modified)):
        if field in doc and parsed is None:
            rep.error(art.rel_path, f"Sigma {field} must be a valid YYYY-MM-DD date")
    if created is not None and modified is not None and modified < created:
        rep.error(art.rel_path, "Sigma modified date must be on or after date")

    status = doc.get("status")
    if status not in (None, "", [], {}) and status not in SIGMA_STATUSES:
        rep.error(
            art.rel_path, f"unsupported Sigma status {status!r}; use {', '.join(SIGMA_STATUSES)}"
        )

    tags = doc.get("tags")
    attack_tags = lib.sigma_attack_tags(doc)
    if not isinstance(tags, list) or any(not _has_text(tag) or tag != tag.strip() for tag in tags):
        rep.error(art.rel_path, "Sigma tags must be a list of non-empty, unpadded strings")
    if not attack_tags:
        rep.error(art.rel_path, "no ATT&CK tag present (expected at least one 'attack.*' tag)")
    tactics = set(lib.load_attack_metadata()["tactics"])
    for tag in sorted(attack_tags - tactics):
        if lib.ATTACK_TECHNIQUE_RE.fullmatch(tag):
            _check_attack_id(tag.upper(), "technique", art.rel_path, rep)
        elif lib.ATTACK_SOFTWARE_RE.fullmatch(tag):
            _check_attack_id(tag.upper(), "software", art.rel_path, rep)
        else:
            rep.error(art.rel_path, f"unknown or malformed ATT&CK tag 'attack.{tag}'")

    rustinel = lib.sigma_rustinel_metadata(doc)
    if "rustinel" in doc and not isinstance(doc["rustinel"], dict):
        rep.error(art.rel_path, "rustinel must be a mapping")
    if "roles" in rustinel:
        roles = rustinel["roles"]
        if not isinstance(roles, list) or not roles:
            rep.error(art.rel_path, "rustinel.roles must be a non-empty list of host roles")
        else:
            for role in roles:
                if not isinstance(role, str) or role not in HOST_ROLES:
                    rep.error(art.rel_path, f"unsupported rustinel.roles value {role!r}")
            if all(isinstance(role, str) for role in roles) and len(set(roles)) != len(roles):
                rep.error(art.rel_path, "rustinel.roles must not contain duplicate roles")
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
        # Rustinel restores the default for temporal at load time. The
        # temporal_ordered evaluator already requires all rules in sequence.
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
    aliases = corr.get("aliases", {})
    if not isinstance(aliases, dict):
        rep.error(where, "correlation aliases must map alias names to rule ids and fields")
        aliases = {}
    alias_fields = {}
    for alias, mapping in aliases.items():
        if not (
            isinstance(alias, str)
            and alias.strip()
            and isinstance(mapping, dict)
            and mapping.keys() == set(rule_ids)
            and all(isinstance(field, str) and field.strip() for field in mapping.values())
        ):
            rep.error(
                where, f"correlation alias {alias!r} must map each referenced rule id to a field"
            )
        else:
            alias_fields[alias] = mapping

    referenced = []
    for rule_id in rule_ids:
        target = sigma_by_id.get(rule_id)
        if target is None:
            rep.error(where, f"correlation references unknown Sigma rule id '{rule_id}'")
        elif lib.is_correlation(target.meta):
            rep.error(where, f"correlation references another correlation '{rule_id}'")
        else:
            referenced.append(target)

    products = {lib.contract_key(t.meta.get("logsource") or {})[0] for t in referenced}
    if len(products) > 1:
        rep.error(where, f"correlation mixes rules for {sorted(products)}; use one platform")

    telemetry = set(lib.sigma_rustinel_metadata(doc).get("telemetry") or [])
    for target in referenced:
        logsource = target.meta.get("logsource") or {}
        missing = set(lib.sigma_rustinel_metadata(target.meta).get("telemetry") or []) - telemetry
        if missing:
            rep.error(
                where,
                f"rustinel.telemetry lacks {sorted(missing)} needed by referenced rule "
                f"'{target.id}'",
            )
        product, category = lib.contract_key(logsource)
        blocked = never_populated.get((product, category), {})
        for group in group_by:
            field = alias_fields[group][target.id] if group in alias_fields else group
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
    product, category = lib.contract_key(logsource)
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


def check_collected_event_ids(art, rep: Report, collected: engine_contract.EventIds):
    """Reject a rule that selects an event ID its channel never collects."""
    doc = art.meta
    if not isinstance(doc, dict):
        return
    logsource = doc.get("logsource") or {}
    product, category = lib.contract_key(logsource)
    if category not in EVENT_ID_ROUTED_CATEGORIES:
        return
    known = collected.get((product, category), set())
    for event_id in sorted(lib.selected_event_ids(doc.get("detection") or {}) - known):
        rep.error(
            art.rel_path,
            f"selects EventID {event_id}, which Rustinel does not collect on "
            f"{product}/{category} (collected: {', '.join(sorted(known, key=int)) or 'none'}).",
        )


def check_yara_rule(art, rep: Report, compile_yara=None):
    raw = art.raw
    if not art.id:
        rep.error(art.rel_path, "YARA rule missing meta id / rule name")
    for technique in lib.artifact_attack_techniques(art):
        _check_attack_id(technique, "technique", art.rel_path, rep)
    for software in lib.artifact_attack_software(art):
        _check_attack_id(software, "software", art.rel_path, rep)
    references = [art.meta[key] for key in ("reference", "references") if key in art.meta]
    if art.path.is_relative_to(lib.RULES_DIR / "yara"):
        check_references(references, art.rel_path, rep)
    elif not references and "attack" not in art.meta:
        rep.warn(art.rel_path, "no attack/reference metadata")
    if compile_yara is not None:
        # Real compile gate (yara-x) supersedes the structural brace/condition checks.
        compile_yara(raw, art.rel_path, rep)
    else:
        if raw.count("{") != raw.count("}"):
            rep.error(art.rel_path, "unbalanced braces in YARA rule")
        if "condition:" not in raw:
            rep.error(art.rel_path, "YARA rule has no 'condition:' section")


@lru_cache(maxsize=1)
def load_ioc_warninglists() -> tuple[
    tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...], tuple[str, ...]
]:
    data = json.loads(IOC_WARNINGLISTS_PATH.read_text(encoding="utf-8"))
    networks = tuple(
        ipaddress.ip_network(value)
        for value in data["special_use_networks"] + data["public_dns_resolvers"]
    )
    return networks, tuple(data["domain_suffixes"])


def _check_ioc_value(ioc_type: str, value: str, where: str, rep: Report, *, production: bool):
    if ";" in value:
        rep.error(where, f"IOC value contains ';' (the file delimiter): '{value}'")
        return
    if ioc_type == "hashes":
        if not (_HEX_RE.match(value) and len(value) in VALID_HASH_LENGTHS):
            rep.error(where, f"invalid hash (expected hex MD5/SHA1/SHA256): '{value}'")
    elif ioc_type == "ips":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            rep.error(where, f"invalid IP/CIDR: '{value}'")
            return
        if production:
            if isinstance(network, ipaddress.IPv6Network) and network.prefixlen >= 96:
                mapped = network.network_address.ipv4_mapped
                if mapped is not None:
                    network = ipaddress.IPv4Network((mapped, network.prefixlen - 96))
            networks, _ = load_ioc_warninglists()
            for blocked in networks:
                if network.overlaps(blocked):
                    rep.error(
                        where, f"IOC IP/CIDR '{value}' overlaps warninglist network {blocked}"
                    )
                    break
    elif ioc_type == "domains":
        if not _DOMAIN_RE.fullmatch(value):
            rep.error(where, f"invalid domain: '{value}'")
            return
        if production:
            _, suffixes = load_ioc_warninglists()
            domain = value.lower().removeprefix("*").strip(".")
            for suffix in suffixes:
                if domain == suffix or domain.endswith(f".{suffix}"):
                    rep.error(where, f"IOC domain '{value}' matches warninglist suffix '{suffix}'")
                    break
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

    production = art.path.is_relative_to(lib.RULES_DIR / "ioc")
    for technique in sorted(lib.artifact_attack_techniques(art)):
        _check_attack_id(technique, "technique", where, rep)

    indicators = lib.parse_ioc_indicators(doc)
    total = sum(len(v) for v in indicators.values())
    if total == 0:
        rep.error(where, "IOC set has no indicators")
    for ioc_type, entries in indicators.items():
        for value, _comment in entries:
            _check_ioc_value(ioc_type, value, where, rep, production=production)

    if production:
        check_references(doc.get("references"), where, rep)
    elif not doc.get("references"):
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


def _has_text(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def check_tuning_and_negatives(art: lib.Artifact, rep: Report, *, min_negatives: int = 1):
    rustinel = lib.sigma_rustinel_metadata(art.meta)
    where = art.rel_path
    tuning = rustinel.get("tuning")
    if not isinstance(tuning, list) or not tuning:
        rep.error(where, "rule needs rustinel.tuning (the surfaces an operator filters)")
    else:
        for item in tuning:
            if not (
                isinstance(item, dict)
                and _has_text(item.get("surface"))
                and _has_text(item.get("guidance"))
            ):
                rep.error(where, "each rustinel.tuning entry needs 'surface' and 'guidance'")

    negatives = rustinel.get("negatives")
    if not isinstance(negatives, list) or not negatives:
        rep.error(where, "rule needs rustinel.negatives (benign events it must ignore)")
        return
    distinct = []
    for item in negatives:
        if not (
            isinstance(item, dict)
            and _has_text(item.get("reason"))
            and isinstance(item.get("fields"), dict)
            and item["fields"]
        ):
            rep.error(where, "each rustinel.negatives entry needs 'reason' and 'fields'")
        elif item["fields"] not in distinct:
            distinct.append(item["fields"])
    if min_negatives > 1 and len(distinct) < min_negatives:
        rep.error(where, f"stable rule needs at least {min_negatives} distinct rustinel.negatives")


def check_advanced_documentation(packs, artifacts, rep: Report):
    """Apply the pack evidence requirements to rules outside the promotion checks."""
    for art in lib.advanced_sigma_rules(packs, artifacts):
        if art.meta.get("status") not in lib.PROMOTED_SIGMA_STATUSES:
            check_tuning_and_negatives(art, rep)


def load_gating_sigma_atomics(
    atomic_dir: Path, titles: Mapping[str, str | None]
) -> set[tuple[str, str]]:
    """Positive manifest entries that run in CI and have a script in the harness."""
    tests = json.loads((atomic_dir / "manifest.json").read_text(encoding="utf-8"))["tests"]
    atomics = (atomic_dir / "atomics").resolve()
    pairs = set()
    for test in tests:
        if test.get("engine") != "sigma" or test.get("allow_failure") or "skip" in test:
            continue
        title = titles.get(test["id"])
        if not title:
            continue
        # The harness defaults to the rule's title. A custom predicate must
        # preserve the title check so an unrelated alert cannot pass the test.
        expect = test.get("expect")
        if expect and not any(
            isinstance(item, dict)
            and item.get("field") == "rule.name"
            and item.get("equals") == title
            for item in (expect if isinstance(expect, list) else [expect])
        ):
            continue
        script_name = test.get("script")
        if not isinstance(script_name, str) or not script_name.strip():
            continue
        script = (atomics / script_name).resolve()
        if script.is_relative_to(atomics) and script.is_file():
            pairs.add((test["platform"], test["id"]))
    return pairs


def check_sigma_lifecycle(
    art: lib.Artifact, pack_platforms: set[str], atomics: set[tuple[str, str]], rep: Report
):
    status = art.meta.get("status")
    rustinel = lib.sigma_rustinel_metadata(art.meta)
    where = art.rel_path
    if status == "deprecated":
        if not _has_text(rustinel.get("deprecation_reason")):
            rep.error(where, "deprecated rule needs rustinel.deprecation_reason")
        if pack_platforms:
            rep.error(where, "deprecated rule must be removed from all production packs")
        return
    if status not in lib.PROMOTED_SIGMA_STATUSES:
        if rustinel.get("test_status") == "manual" and not _has_text(rustinel.get("test_reason")):
            rep.error(where, "manual rule needs rustinel.test_reason")
        return

    if rustinel.get("test_status") != "atomic":
        rep.error(where, f"{status} rule needs rustinel.test_status: atomic")
    platforms = pack_platforms or {art.path.relative_to(lib.RULES_DIR / "sigma").parts[0]}
    for platform in sorted(platforms):
        if (platform, art.id) not in atomics:
            rep.error(where, f"{status} rule needs a gating positive Sigma atomic on {platform}")

    if not _has_text(art.meta.get("author")):
        rep.error(where, f"{status} rule needs author attribution")
    if rustinel.get("expected_false_positive_level") not in ("low", "medium", "high"):
        rep.error(where, f"{status} rule needs rustinel.expected_false_positive_level")

    check_tuning_and_negatives(art, rep, min_negatives=2 if status == "stable" else 1)
    if status == "stable":
        falsepositives = art.meta.get("falsepositives")
        if (
            not isinstance(falsepositives, list)
            or not falsepositives
            or not all(_has_text(item) for item in falsepositives)
        ):
            rep.error(where, "stable rule needs falsepositives documenting known benign matches")


def check_packs(packs, artifacts, rep: Report, preview_by_id=None):
    schema_validate = load_schema_validator(lib.PACK_SCHEMA_PATH)
    if schema_validate is None:
        rep.warn("schema", "jsonschema not installed; using minimal field checks only")

    by_id = {p["id"]: p for p in packs if "id" in p}
    artifact_index = {a.id: a for a in artifacts if a.id}
    preview_by_id = preview_by_id or {}
    sigma_platforms: dict[str, set[str]] = {}

    for pack in packs:
        where = str(Path(pack["__path__"]).relative_to(lib.REPO_ROOT))

        # Minimal required-field check (works without jsonschema).
        for field in REQUIRED_PACK_FIELDS:
            if field not in pack:
                rep.error(where, f"missing required field '{field}'")
        if pack.get("level") == "hunting" and pack.get("active_response_eligible") is not False:
            rep.error(
                where,
                "hunting packs must set 'active_response_eligible: false' "
                "(hunting content is not eligible for active response)",
            )
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
            if artifact is None or artifact.kind != "sigma":
                continue
            if pack.get("os") in ("linux", "macos", "windows"):
                sigma_platforms.setdefault(rule_id, set()).add(pack["os"])
            if not lib.is_correlation(artifact.meta):
                continue
            for ref in lib.correlation_rule_ids(artifact.meta):
                if ref not in members:
                    rep.error(
                        where,
                        f"correlation '{rule_id}' references '{ref}', which is not in this pack",
                    )

        # Drift guard: coverage and test status are derived from member rules,
        # so the manifest must say exactly what the content supports.
        summary = lib.derive_pack_summary(resolved, artifact_index)
        declared = {str(t).upper() for t in pack.get("attack_coverage") or []}
        derived_techniques = set(summary["attack_coverage"])
        for technique in sorted(declared - derived_techniques):
            rep.error(where, f"attack_coverage '{technique}' not found in any member artifact")
        for technique in sorted(derived_techniques - declared):
            rep.error(where, f"attack_coverage is missing '{technique}', covered by a member rule")
        if pack.get("test_status") != summary["test_status"]:
            rep.error(
                where,
                f"test_status is {pack.get('test_status')!r} but member rules roll up to "
                f"{summary['test_status']!r}",
            )
    return sigma_platforms


def check_preview(preview_artifacts, rep: Report, ioc_schema_validate, compile_yara):
    """The preview tree is validated like production content, plus its register.

    Preview rules still need core metadata for parsing and staging. Production
    lifecycle evidence and field availability are checked when they ship.
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
            check_sigma_rule(art, rep, production=False)
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


def check_sigma_history(base: str, artifacts: list[lib.Artifact], rep: Report):
    """Check existing Sigma rules against a base revision, including Git-detected renames."""

    def git(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=lib.REPO_ROOT, encoding="utf-8")

    revision = git("rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}").strip()
    changes = git(
        "diff",
        "--name-status",
        "-z",
        "--find-renames",
        "--diff-filter=MR",
        revision,
        "--",
        "rules/sigma/",
        "preview/sigma/",
    )
    by_path = {art.path.relative_to(lib.REPO_ROOT).as_posix(): art for art in artifacts}
    fields = iter(changes.rstrip("\0").split("\0")) if changes else iter(())
    for status in fields:
        old_path = next(fields)
        new_path = next(fields) if status.startswith("R") else old_path
        artifact = by_path.get(new_path)
        if artifact is None:
            continue
        old = yaml.safe_load(git("show", f"{revision}:{old_path}"))
        new = artifact.meta
        if old.get("id") != new.get("id"):
            rep.error(artifact.rel_path, f"keep the existing Sigma id '{old.get('id')}'")
        behavior_fields = ("detection", "logsource", "correlation")
        if all(old.get(field) == new.get(field) for field in behavior_fields):
            continue
        prior_modified = _iso_date(old.get("modified"))
        previous = prior_modified or _iso_date(old.get("date"))
        modified = _iso_date(new.get("modified"))
        same_day = (
            modified is not None
            and modified == prior_modified
            and modified == _iso_date(git("log", "-1", "--format=%cs", "--", new_path).strip())
        )
        if (
            modified is None
            or (previous is not None and modified < previous)
            or (modified == prior_modified and not same_day)
        ):
            rep.error(
                artifact.rel_path, "update the Sigma modified date when detection behavior changes"
            )


def main(argv: Sequence[str] = ()) -> int:
    parser = argparse.ArgumentParser(description="Validate Rustinel detection content.")
    parser.add_argument("--base", help="Git revision to check for changed Sigma IDs and logic")
    args = parser.parse_args(argv)
    rep = Report()

    try:
        engine_pin, never_populated = engine_contract.load_contract()
        collected_event_ids = engine_contract.load_event_ids()
    except (OSError, ValueError) as exc:
        print(f"[ERROR] engine field contract: {exc}")
        return 1
    try:
        lib.load_attack_metadata()
        load_ioc_warninglists()
    except (OSError, ValueError, KeyError) as exc:
        print(f"[ERROR] ATT&CK metadata or IOC warninglists: {exc}")
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
    try:
        gating_atomics = load_gating_sigma_atomics(
            ATOMIC_DIR, {rule_id: art.meta.get("title") for rule_id, art in sigma_by_id.items()}
        )
    except (OSError, ValueError, KeyError) as exc:
        print(f"[ERROR] atomic manifest: {exc}")
        return 1
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
    sigma_platforms = check_packs(packs, artifacts, rep, preview_by_id)
    for rule_id, art in sigma_by_id.items():
        check_sigma_lifecycle(art, sigma_platforms.get(rule_id, set()), gating_atomics, rep)
    check_advanced_documentation(packs, artifacts, rep)
    if args.base:
        try:
            check_sigma_history(args.base, [a for a in artifacts if a.kind == "sigma"], rep)
        except (OSError, subprocess.CalledProcessError, yaml.YAMLError) as exc:
            rep.error("Sigma history", str(exc))

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
    sys.exit(main(sys.argv[1:]))
