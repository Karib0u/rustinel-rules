"""Read the vendored engine field contract without network access."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import lib

CONTRACT_PATH = lib.REPO_ROOT / "compatibility" / "field-availability.json"
PIN_PATH = lib.REPO_ROOT / "compatibility" / "engine.json"

# Contract schemas this tooling understands. Schema 2 (engine v1.7.1+) adds a
# `since` release to every row and an optional `value`. Schema 3 (engine main,
# not yet released) adds `view`; it needs a tooling update before vendoring.
SUPPORTED_SCHEMAS = {1, 2}

_SINCE_RE = re.compile(r"\d+\.\d+\.\d+")

# Fields the engine does not populate but the contract has no row for. A
# contract row for the same field supersedes its override automatically.
FIELD_OVERRIDES = {
    # Schema 1 omits ParentUser; v1.6.0 does not resolve the parent's user.
    # Superseded by its own row from the v1.8.0 contract onward.
    ("windows", "process_creation", "ParentUser"): "ETW does not resolve the parent's user",
    # No contract row: the ETW process path does not resolve logon sessions.
    ("windows", "process_creation", "LogonId"): "no logon ID resolution on the ETW process path",
    # The contract has LogonGuid only for Security events, not process creation.
    ("windows", "process_creation", "LogonGuid"): "ETW does not resolve process logon GUIDs",
}

# Known-wrong `since` values in a released contract, keyed by that release:
# {pinned version: {published since: corrected since}}. Keyed by the pin, so a
# correction stops applying as soon as the pin moves past the faulty release.
SINCE_CORRECTIONS = {
    # v1.8.0 stamped the rows it introduced with the previous release, 1.7.1.
    # Diffing the v1.7.1 and v1.8.0 contracts shows 481 of its 482 non-never
    # "1.7.1" rows were new in 1.8.0; the last is Linux CurrentDirectory, whose
    # guarantee changed in 1.8.0. Engine main dates every one of them 1.8.0.
    "1.8.0": {"1.7.1": "1.8.0"},
}

BlockedFields = dict[tuple[str, str], dict[str, tuple[str, ...]]]
# {(platform, category): {field: first release it is populated, None = always}}
FieldSince = dict[tuple[str, str], dict[str, str | None]]


def parse_contract(raw: bytes) -> BlockedFields:
    """Block a field only when every event source for it says 'never'."""
    doc = json.loads(raw)
    if not isinstance(doc, dict) or type(doc.get("schema_version")) is not int:
        raise ValueError("field contract must declare an integer schema_version")
    schema = doc["schema_version"]
    if schema not in SUPPORTED_SCHEMAS:
        raise ValueError(f"unsupported field contract schema_version {schema!r}")
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("field contract entries must be a non-empty list")

    groups: dict[tuple[str, str, str], list[dict]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"field contract entry {index} must be an object")
        for key in ("platform", "category", "provider", "source", "field", "availability"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise ValueError(f"field contract entry {index} has invalid {key}")
        if entry["availability"] not in {"always", "conditional", "never"}:
            raise ValueError(f"field contract entry {index} has unknown availability")
        if entry["availability"] == "never" and (
            not isinstance(entry.get("reason"), str) or not entry["reason"].strip()
        ):
            raise ValueError(f"field contract entry {index} marked never needs a reason")
        if schema >= 2:
            # Required from schema 2: null means the availability predates the
            # oldest release the engine supports.
            if "since" not in entry:
                raise ValueError(f"field contract entry {index} is missing since")
            since = entry["since"]
            if since is not None and not (isinstance(since, str) and _SINCE_RE.fullmatch(since)):
                raise ValueError(f"field contract entry {index} has invalid since")
        key = (entry["platform"], entry["category"], entry["field"])
        groups.setdefault(key, []).append(entry)

    blocked: BlockedFields = {}
    for (platform, category, field), rows in groups.items():
        if all(row["availability"] == "never" for row in rows):
            reasons = tuple(dict.fromkeys(row["reason"] for row in rows))
            blocked.setdefault((platform, category), {})[field] = reasons
    for (platform, category, field), reason in FIELD_OVERRIDES.items():
        if (platform, category, field) not in groups:
            blocked.setdefault((platform, category), {})[field] = (reason,)
    return blocked


def parse_field_since(raw: bytes, version: str) -> FieldSince:
    """The first release in which each field is populated by some event source.

    A field is usable as soon as one of its non-never rows is, so the earliest
    `since` wins; null (predates the oldest supported release) beats any
    version. Schema 1 carries no `since`, so it yields an empty map. Call
    parse_contract first: this assumes a contract it accepted.
    """
    doc = json.loads(raw)
    corrections = SINCE_CORRECTIONS.get(version, {})
    result: FieldSince = {}
    if doc["schema_version"] < 2:
        return result
    for entry in doc["entries"]:
        if entry["availability"] == "never":
            continue
        since = entry["since"]
        since = corrections.get(since, since) if since is not None else None
        fields = result.setdefault((entry["platform"], entry["category"]), {})
        current = fields.get(entry["field"], "")
        if current is None:
            continue
        if since is None or current == "" or lib.parse_version(since) < lib.parse_version(current):
            fields[entry["field"]] = since
    return result


def read_pin(path: Path = PIN_PATH) -> dict:
    pin = json.loads(path.read_bytes())
    if not isinstance(pin, dict):
        raise ValueError("engine pin must be an object")
    for key, pattern in (
        ("version", r"\d+\.\d+\.\d+"),
        ("revision", r"[0-9a-f]{40}"),
        ("field_availability_sha256", r"[0-9a-f]{64}"),
    ):
        if not isinstance(pin.get(key), str) or not re.fullmatch(pattern, pin[key]):
            raise ValueError(f"engine pin has invalid {key}")
    return pin


def load_contract(
    contract_path: Path = CONTRACT_PATH, pin_path: Path = PIN_PATH
) -> tuple[dict, BlockedFields]:
    pin = read_pin(pin_path)
    raw = contract_path.read_bytes()
    blocked = parse_contract(raw)
    if hashlib.sha256(raw).hexdigest() != pin["field_availability_sha256"]:
        raise ValueError("field contract checksum differs from engine pin; refresh them together")
    # Report which schema was read alongside the pin it belongs to.
    return {**pin, "schema_version": json.loads(raw)["schema_version"]}, blocked


def load_field_since(contract_path: Path = CONTRACT_PATH, pin_path: Path = PIN_PATH) -> FieldSince:
    """Field release map of the vendored contract, checked like load_contract."""
    pin, _ = load_contract(contract_path, pin_path)
    return parse_field_since(contract_path.read_bytes(), pin["version"])
