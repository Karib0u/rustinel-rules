#!/usr/bin/env python3
"""Check built packs against the engine's rules-install contract.

`rustinel setup` and `rustinel rules list|install|update` read dist/index.json and
the pack zips. This repeats the checks the engine makes before it installs a pack
(src/rules.rs in Karib0u/rustinel), so a build that engines would refuse fails
here instead of on users' hosts. One malformed pack entry makes the engine reject
the whole catalog, on every platform.

Checks:
  - catalog: schema, release_version, at least one pack
  - each pack: required fields, os, artifact (a .zip file in dist/), sha256,
    requires_rustinel
  - each archive: size limits, safe entry paths, no symlinks, pack.yml fields,
    manifest/catalog agreement, sigma/ yara/ ioc/ and the four IOC files
  - each pack installs on the certified engine (compatibility/engine.json)
  - against the last published catalog: no pack id disappears, release_version
    does not go backwards (with --release it must move forward), and
    requires_rustinel changes are reported

Exit code 0 = all checks pass, 1 = one or more failures.

Run (after build_packs.py):
  uv run python tools/check_engine_install.py [--baseline URL|PATH|none] [--release]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

import yaml

import engine_contract
import lib

# Constants and field lists mirror src/rules.rs.
INDEX_SCHEMA = "rustinel-rules/index@1"
SUPPORTED_PACK_SCHEMA_VERSIONS = (1, 2)
SUPPORTED_OS = ("windows", "linux", "macos")
MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_BYTES = 250 * 1024 * 1024
IOC_FILES = ("hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt")
CATALOG_PACK_FIELDS = (
    "id",
    "name",
    "os",
    "level",
    "version",
    "requires_rustinel",
    "status",
    "artifact",
    "sha256",
)
MANIFEST_FIELDS = {
    "name": str,
    "id": str,
    "description": str,
    "os": str,
    "level": str,
    "pack_schema_version": int,
    "requires_rustinel": str,
    "default": bool,
    "status": str,
    "extends": list,
}

DEFAULT_BASELINE = "https://github.com/Karib0u/rustinel-rules/releases/latest/download/index.json"

# The engine parses requires_rustinel as a semver VersionReq. Accept only the
# subset build_packs.py emits: comma-separated comparators on full versions.
_COMPARATOR_RE = re.compile(r"^(>=|<=|>|<|=)\s*(\d+)\.(\d+)\.(\d+)$")


class Report:
    def __init__(self):
        self.errors: list[str] = []
        self.notes: list[str] = []

    def error(self, where: str, msg: str):
        self.errors.append(f"[ERROR] {where}: {msg}")

    def note(self, where: str, msg: str):
        self.notes.append(f"[NOTE]  {where}: {msg}")

    def ok(self) -> bool:
        return not self.errors


def parse_requirement(text: str) -> list[tuple[str, tuple[int, int, int]]]:
    """'>=1.4.1' -> [('>=', (1, 4, 1))]. Raises ValueError outside the subset."""
    comparators = []
    for part in str(text).split(","):
        match = _COMPARATOR_RE.fullmatch(part.strip())
        if not match:
            raise ValueError(
                f"{text!r} is not a comma-separated list of >=, >, <=, < or = "
                f"comparators on full X.Y.Z versions"
            )
        op, *nums = match.groups()
        comparators.append((op, (int(nums[0]), int(nums[1]), int(nums[2]))))
    return comparators


def requirement_matches(text: str, version: str) -> bool:
    current = lib.parse_version(version)
    checks = {
        ">=": lambda v: current >= v,
        ">": lambda v: current > v,
        "<=": lambda v: current <= v,
        "<": lambda v: current < v,
        "=": lambda v: current == v,
    }
    return all(checks[op](v) for op, v in parse_requirement(text))


def unsafe_entry_reason(name: str) -> str | None:
    """Why the engine's safe_zip_path would refuse this entry, if it would."""
    if not name or "\\" in name:
        return "empty name or backslash"
    if name.startswith("/"):
        return "absolute path"
    parts = name[:-1].split("/") if name.endswith("/") else name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return "empty, '.' or '..' component"
    return None


def check_archive(pack: dict, data: bytes, rep: Report):
    where = pack["id"]
    if len(data) > MAX_ARTIFACT_BYTES:
        rep.error(
            where,
            f"artifact is {len(data)} bytes; the engine downloads at most {MAX_ARTIFACT_BYTES}",
        )
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        rep.error(where, f"artifact is not a readable zip: {exc}")
        return
    infos = archive.infolist()
    extracted = 0
    for info in infos:
        reason = unsafe_entry_reason(info.filename)
        if reason:
            rep.error(where, f"zip entry {info.filename!r} is unsafe ({reason})")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            rep.error(where, f"zip entry {info.filename!r} is a symlink")
        extracted += info.file_size
    if extracted > MAX_EXTRACTED_BYTES:
        rep.error(
            where, f"zip extracts to {extracted} bytes; the engine allows {MAX_EXTRACTED_BYTES}"
        )

    names = {info.filename for info in infos}
    if "pack.yml" not in names:
        rep.error(where, "zip has no top-level pack.yml")
        return
    try:
        manifest = yaml.safe_load(archive.read("pack.yml"))
    except yaml.YAMLError as exc:
        rep.error(where, f"pack.yml does not parse: {exc}")
        return
    if not isinstance(manifest, dict):
        rep.error(where, "pack.yml is not a mapping")
        return
    for field, kind in MANIFEST_FIELDS.items():
        value = manifest.get(field)
        if field not in manifest:
            rep.error(where, f"pack.yml is missing required field {field!r}")
        elif not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            rep.error(
                where, f"pack.yml {field!r} must be {kind.__name__}, got {type(value).__name__}"
            )
        elif (
            kind is str
            and field in ("name", "description", "level", "status")
            and not value.strip()
        ):
            rep.error(where, f"pack.yml {field!r} is empty")
    if manifest.get("pack_schema_version") not in SUPPORTED_PACK_SCHEMA_VERSIONS:
        rep.error(
            where,
            f"pack_schema_version {manifest.get('pack_schema_version')!r} is not one of "
            f"{SUPPORTED_PACK_SCHEMA_VERSIONS}; every released engine would refuse the pack",
        )
    for field in ("id", "os", "requires_rustinel"):
        if field in manifest and manifest[field] != pack.get(field):
            rep.error(
                where,
                f"pack.yml {field} {manifest[field]!r} does not match "
                f"index.json {pack.get(field)!r}",
            )

    def has_dir(prefix: str) -> bool:
        return any(name.startswith(prefix) for name in names)

    root = next(
        (r for r in ("", "rules/") if all(has_dir(f"{r}{d}/") for d in ("sigma", "yara", "ioc"))),
        None,
    )
    if root is None:
        rep.error(where, "zip needs sigma/, yara/ and ioc/ at its root or under rules/")
        return
    for name in IOC_FILES:
        if f"{root}ioc/{name}" not in names:
            rep.error(
                where, f"zip is missing {root}ioc/{name}; the engine requires all four IOC files"
            )


def check_pack(pack: dict, dist: Path, pin_version: str, rep: Report):
    where = str(pack.get("id") or "<pack without id>")
    missing = [
        f for f in CATALOG_PACK_FIELDS if not isinstance(pack.get(f), str) or not pack[f].strip()
    ]
    if missing:
        rep.error(where, f"index.json entry is missing or has empty {', '.join(missing)}")
        return
    if pack["os"] not in SUPPORTED_OS:
        rep.error(where, f"os {pack['os']!r} is not one of {SUPPORTED_OS}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", pack["sha256"]):
        rep.error(where, "sha256 is not 64 hex characters")
    try:
        if not requirement_matches(pack["requires_rustinel"], pin_version):
            rep.error(
                where,
                f"requires Rustinel {pack['requires_rustinel']}, which the certified engine "
                f"v{pin_version} does not satisfy, so CI never tested it. Move the pin first.",
            )
    except ValueError as exc:
        rep.error(where, f"requires_rustinel: {exc}")
    # The engine resolves the artifact relative to the catalog URL, and release.yml
    # uploads dist/*.zip, so it must be a bare .zip file name.
    artifact = pack["artifact"]
    if "/" in artifact or "\\" in artifact or not artifact.endswith(".zip"):
        rep.error(where, f"artifact {artifact!r} must be a .zip file name with no directory")
        return
    path = dist / artifact
    if not path.is_file():
        rep.error(where, f"artifact {artifact} is not in {dist}")
        return
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != pack["sha256"].lower():
        rep.error(where, f"sha256 does not match {artifact}")
    check_archive(pack, data, rep)


def check_catalog(catalog, dist: Path, pin_version: str, rep: Report):
    if not isinstance(catalog, dict):
        rep.error("index.json", "is not an object")
        return
    if catalog.get("schema") != INDEX_SCHEMA:
        rep.error("index.json", f"schema {catalog.get('schema')!r} is not {INDEX_SCHEMA!r}")
    if not str(catalog.get("release_version") or "").strip():
        rep.error("index.json", "release_version is empty")
    packs = catalog.get("packs")
    if not isinstance(packs, list) or not packs:
        rep.error("index.json", "has no packs")
        return
    for pack in packs:
        if isinstance(pack, dict):
            check_pack(pack, dist, pin_version, rep)
        else:
            rep.error("index.json", "pack entry is not an object")


def compare_baseline(catalog: dict, baseline: dict, release: bool, rep: Report) -> list[tuple]:
    """Return (id, old requires, new requires) rows for every pack."""
    current = {p.get("id"): p for p in catalog.get("packs") or [] if isinstance(p, dict)}
    previous = {p.get("id"): p for p in baseline.get("packs") or [] if isinstance(p, dict)}
    published = str(baseline.get("release_version") or "?")
    for pack_id in sorted(set(previous) - set(current), key=str):
        rep.error(
            str(pack_id),
            f"was published in v{published} and is missing now. A host with this pack "
            f"active would fail 'rustinel rules update' (not found in the catalog).",
        )
    new, old = str(catalog.get("release_version") or ""), published
    if lib.parse_version(new) < lib.parse_version(old):
        rep.error("index.json", f"release_version {new} is older than the published v{old}")
    elif lib.parse_version(new) == lib.parse_version(old):
        message = (
            f"release_version {new} equals the published version, "
            f"so 'rustinel rules update' would not offer it"
        )
        if release:
            rep.error("index.json", message)
        else:
            rep.note("index.json", f"{message}; bump pyproject.toml before tagging")
    rows = []
    for pack_id in sorted(set(current) | set(previous), key=str):
        before = (previous.get(pack_id) or {}).get("requires_rustinel", "-")
        after = (current.get(pack_id) or {}).get("requires_rustinel", "-")
        rows.append((pack_id, before, after))
        if pack_id in current and pack_id in previous and before != after:
            rep.note(
                str(pack_id),
                f"requires_rustinel changes {before} -> {after}; engines outside the new range "
                f"will refuse 'rustinel rules install|update' for this pack",
            )
    return rows


def load_baseline(source: str) -> dict:
    if source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=30) as response:
            return json.loads(response.read())
    return json.loads(Path(source).read_bytes())


def write_summary(rows: list[tuple], published: str, rep: Report):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = [
        "### Engine install check",
        "",
        f"`requires_rustinel` against the published v{published}:",
        "",
        "| Pack | Published | This build |",
        "| --- | --- | --- |",
    ]
    for pack_id, before, after in rows:
        mark = " (changed)" if before != after else ""
        lines.append(f"| `{pack_id}` | `{before}` | `{after}`{mark} |")
    lines += ["", "**Result:** " + ("pass" if rep.ok() else f"{len(rep.errors)} error(s)"), ""]
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check built packs against the engine's install contract."
    )
    parser.add_argument(
        "--dist", type=Path, default=lib.DIST_DIR, help="Build output (default: dist/)"
    )
    parser.add_argument(
        "--baseline",
        default=DEFAULT_BASELINE,
        help="Published index.json to compare with: an https URL, a path, or 'none' "
        "(default: latest release)",
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help="Release build: release_version must be newer than the baseline's",
    )
    args = parser.parse_args(argv)

    rep = Report()
    pin_version = engine_contract.read_pin()["version"]
    index_path = args.dist / "index.json"
    if not index_path.is_file():
        print(f"[ERROR] {index_path} not found; run build_packs.py first")
        return 1
    catalog = json.loads(index_path.read_bytes())
    check_catalog(catalog, args.dist, pin_version, rep)

    if args.baseline != "none" and isinstance(catalog, dict):
        try:
            baseline = load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"[ERROR] could not read the baseline catalog {args.baseline}: {exc}")
            print("        Pass --baseline none to skip the comparison when offline.")
            return 1
        rows = compare_baseline(catalog, baseline, args.release, rep)
        write_summary(rows, str(baseline.get("release_version") or "?"), rep)

    for line in rep.notes + rep.errors:
        print(line)
    packs = len(catalog.get("packs") or []) if isinstance(catalog, dict) else 0
    if not rep.ok():
        print(
            f"FAILED - {len(rep.errors)} error(s); "
            "engines would refuse this catalog or a pack in it."
        )
        return 1
    print(f"OK - {packs} packs pass the engine install contract (certified engine v{pin_version}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
