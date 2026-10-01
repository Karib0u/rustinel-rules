"""Read the vendored engine field contract without network access."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import lib

CONTRACT_PATH = lib.REPO_ROOT / "compatibility" / "field-availability.json"
PIN_PATH = lib.REPO_ROOT / "compatibility" / "engine.json"

# A future contract row supersedes each override.
FIELD_OVERRIDES = {
    # Schema 1 omits ParentUser; v1.6.0 does not resolve the parent's user.
    ("windows", "process_creation", "ParentUser"): "ETW does not resolve the parent's user",
    # Schema 1 omits process LogonId; v1.6.0 does not resolve logon sessions.
    ("windows", "process_creation", "LogonId"): "no logon ID resolution on the ETW process path",
    # Schema 1 has LogonGuid only for Security events, not process creation.
    ("windows", "process_creation", "LogonGuid"): "ETW does not resolve process logon GUIDs",
}

BlockedFields = dict[tuple[str, str], dict[str, tuple[str, ...]]]


def parse_contract(raw: bytes) -> BlockedFields:
    """Block a field only when every event source for it says 'never'."""
    doc = json.loads(raw)
    if not isinstance(doc, dict) or type(doc.get("schema_version")) is not int:
        raise ValueError("field contract must declare an integer schema_version")
    if doc["schema_version"] != 1:
        raise ValueError(f"unsupported field contract schema_version {doc['schema_version']!r}")
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
    return pin, blocked
