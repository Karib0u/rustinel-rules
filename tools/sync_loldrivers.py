#!/usr/bin/env python3
"""Sync verified vulnerable driver SHA-256 hashes from pinned LOLDrivers records."""

import re
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

import lib
from sync_ioc import clean_text, sync

REPOSITORY = "https://github.com/magicsword-io/LOLDrivers"
REVISION = "3fe1f4c5cf18f01953317a8850f5cefdde10123d"
OUTPUT = lib.RULES_DIR / "ioc/windows/ioc_loldrivers_vulnerable_hashes.yml"
SHA256 = re.compile(r"[0-9a-f]{64}")
CVE = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,}\b", re.IGNORECASE)


def collect(records: list[tuple[str, dict]], warninglists: dict) -> list[dict[str, str]]:
    # The shared warninglist currently contains domains and networks. Honor
    # exact SHA-256 entries if a hashes group is added.
    blocked = {value.strip().lower() for value in warninglists.get("hashes", [])}
    filenames: dict[str, set[str]] = defaultdict(set)
    cves: dict[str, set[str]] = defaultdict(set)
    sources: dict[str, set[str]] = defaultdict(set)
    for source, record in records:
        if str(record.get("Verified")).strip().lower() != "true":
            continue
        if str(record.get("Category")).strip().lower() != "vulnerable driver":
            continue
        commands = record.get("Commands") or {}
        if "windows" not in str(commands.get("OperatingSystem", "Windows")).lower():
            continue
        record_id = clean_text(str(record.get("Id") or Path(source).stem))
        cve_text = f"{record.get('CVE')} {record.get('CVEs')} {commands.get('Description')}"
        matches = CVE.findall(cve_text) or CVE.findall(str(record.get("Resources")))
        record_cves = {match.upper() for match in matches}
        for sample in record.get("KnownVulnerableSamples") or []:
            digest = str(sample.get("SHA256", "")).strip().lower()
            if not SHA256.fullmatch(digest) or digest in blocked:
                continue
            names = [
                clean_text(name)
                for name in (sample.get("Filename"), sample.get("OriginalFilename"))
                if isinstance(name, str) and name.strip()
            ]
            if not names:
                names = [
                    clean_text(tag)
                    for tag in record.get("Tags") or []
                    if isinstance(tag, str) and tag.strip()
                ]
            filenames[digest].add(next(iter(names), "Filename unavailable"))
            cves[digest].update(record_cves)
            sources[digest].add(record_id)

    entries = []
    for digest in sorted(sources):
        names = ", ".join(sorted(filenames[digest], key=lambda name: (name.casefold(), name)))
        detail = "vulnerable driver"
        if cves[digest]:
            detail += f" ({', '.join(sorted(cves[digest]))})"
        attribution = ", ".join(sorted(sources[digest]))
        entries.append(
            {
                "value": digest,
                "comment": f"{names} | {detail} | LOLDrivers {REVISION[:12]} ({attribution})",
            }
        )
    return entries


def main(argv: Sequence[str] | None = None) -> int:
    return sync(__doc__, REPOSITORY, REVISION, OUTPUT, "hashes", collect, argv)


if __name__ == "__main__":
    raise SystemExit(main())
