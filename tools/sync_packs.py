#!/usr/bin/env python3
"""Rewrite each pack manifest's derived fields from its member rules.

`attack_coverage` and `test_status` are computed from the rules a pack resolves
to (see lib.derive_pack_summary); `validate.py` rejects a manifest that
disagrees. Run this after changing pack membership or a rule's techniques or
test status. Only those two fields are touched; the rest of the file, comments
included, is left as written.

Run: uv run python tools/sync_packs.py [--check]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import lib

_COVERAGE_RE = re.compile(r"^attack_coverage:\n(?:[ \t]+- .*\n)*", re.MULTILINE)
_STATUS_RE = re.compile(r"^test_status: .*\n", re.MULTILINE)


def render(text: str, summary: dict) -> str:
    block = "attack_coverage:\n" + "".join(f"  - {t}\n" for t in summary["attack_coverage"])
    if not summary["attack_coverage"]:
        block = "attack_coverage: []\n"
    status = f"test_status: {summary['test_status']}\n"
    text = _COVERAGE_RE.sub(lambda _: block, text, count=1) if _COVERAGE_RE.search(text) else text
    if _STATUS_RE.search(text):
        return _STATUS_RE.sub(lambda _: status, text, count=1)
    return text.rstrip("\n") + "\n" + status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if any manifest is stale")
    args = parser.parse_args()

    artifact_index = {a.id: a for a in lib.load_all_artifacts() if a.id}
    packs = lib.load_packs()
    by_id = {p["id"]: p for p in packs}
    stale = 0
    for pack in packs:
        path = Path(pack["__path__"])
        summary = lib.derive_pack_summary(lib.resolve_pack_rules(pack, by_id), artifact_index)
        old = path.read_text()
        new = render(old, summary)
        if new == old:
            continue
        stale += 1
        rel = path.relative_to(lib.REPO_ROOT)
        if args.check:
            print(f"[STALE] {rel}")
        else:
            path.write_text(new)
            print(f"[SYNC]  {rel}")
    return 1 if (args.check and stale) else 0


if __name__ == "__main__":
    sys.exit(main())
