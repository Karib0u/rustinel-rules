#!/usr/bin/env python3
"""Refresh the field contract and its engine pin together from a released tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from urllib.error import URLError
from urllib.request import urlopen

import engine_contract


def refresh(version: str | None = None) -> None:
    if version is None:
        pin = engine_contract.read_pin()
        version, revision = pin["version"], pin["revision"]
    else:
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError("version must be MAJOR.MINOR.PATCH, without a v prefix")
        with urlopen(
            f"https://api.github.com/repos/Karib0u/rustinel/commits/v{version}", timeout=30
        ) as response:
            revision = json.load(response)["sha"]
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("GitHub did not return an exact engine commit")

    with urlopen(
        f"https://raw.githubusercontent.com/Karib0u/rustinel/{revision}"
        "/compatibility/field-availability.json",
        timeout=30,
    ) as response:
        raw = response.read()
    # Validate before replacing either file. Unsupported future schemas need a
    # tooling update, rather than silently disabling the field guard.
    engine_contract.parse_contract(raw)
    pin = {
        "version": version,
        "revision": revision,
        "field_availability_sha256": hashlib.sha256(raw).hexdigest(),
    }
    engine_contract.CONTRACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    engine_contract.CONTRACT_PATH.write_bytes(raw)
    engine_contract.PIN_PATH.write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")
    print(f"Vendored Rustinel {version} field contract at {revision}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", help="released engine version; omit to restore the current pin"
    )
    args = parser.parse_args()
    try:
        refresh(args.version)
    except (OSError, ValueError, KeyError, URLError) as exc:
        print(f"[ERROR] engine contract refresh: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
