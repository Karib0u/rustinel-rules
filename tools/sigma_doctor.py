#!/usr/bin/env python3
"""Run the engine's `rustinel sigma doctor` over built packs and Preview content.

The engine answers "can this rule ever fire here" with its own parser, routing,
collector configuration and field contract, so this tool only applies policy:

  - production (built packs under dist/): fail when a pack cannot be parsed or
    compiled (exit 2), or when any document is `can-never-fire`. `degraded` is a
    warning for now, summarised by reason rather than listed per rule.
  - preview/: report only. A Preview rule that can now fire is a promotion
    candidate; nothing is promoted or failed automatically.

Run `tools/build_packs.py` first, then:
    uv run python tools/sigma_doctor.py --engine tests/atomic/.engine/rustinel
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import yaml

import lib

PLATFORMS = ("windows", "linux", "macos")
SUPPORTED_SCHEMA = 1


def verdict_of(doc: dict) -> str:
    # The summary spells verdicts with underscores, documents with hyphens.
    return str(doc.get("verdict", "")).replace("_", "-")


def run_doctor(engine: Path, platform: str, rules: Path) -> dict:
    """The parsed `sigma doctor --json` report. Exit 0 and 1 both carry a report;
    anything else, or an unreadable report, means the engine could not judge."""
    proc = subprocess.run(
        [str(engine), "sigma", "doctor", "--json", "--platform", platform, "--rules", str(rules)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        detail = (proc.stderr or proc.stdout).strip()[:500]
        raise RuntimeError(f"exit {proc.returncode}: {detail}")
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"report is not JSON: {exc}") from exc
    if not isinstance(report, dict) or report.get("schema_version") != SUPPORTED_SCHEMA:
        raise RuntimeError(f"unsupported report schema {report.get('schema_version')!r}")
    if not isinstance(report.get("documents"), list):
        raise RuntimeError("report has no documents list")
    return report


def reason_counts(docs: list[dict]) -> Counter:
    return Counter(r.get("code", "?") for d in docs for r in d.get("reasons", []))


def production_targets(dist: Path, only: str | None) -> list[tuple[str, str, Path]]:
    """(pack id, platform, sigma dir) for every built pack."""
    targets = []
    for pack_yml in sorted(dist.glob("*/pack.yml")):
        manifest = yaml.safe_load(pack_yml.read_text(encoding="utf-8"))
        platform = manifest.get("os")
        sigma = pack_yml.parent / "sigma"
        if platform not in PLATFORMS:
            raise ValueError(f"{pack_yml}: unknown os {platform!r}")
        if (only is None or platform == only) and sigma.is_dir():
            targets.append((manifest["id"], platform, sigma))
    return targets


def check_production(engine: Path, targets, summary: list[str]) -> list[str]:
    errors = []
    for pack_id, platform, sigma in targets:
        try:
            report = run_doctor(engine, platform, sigma)
        except RuntimeError as exc:
            errors.append(f"{pack_id}: sigma doctor failed ({exc})")
            continue
        docs = report["documents"]
        never = [d for d in docs if verdict_of(d) == "can-never-fire"]
        degraded = [d for d in docs if verdict_of(d) == "degraded"]
        for doc in never:
            codes = ", ".join(r.get("code", "?") for r in doc.get("reasons", [])) or "no reason"
            errors.append(f"{pack_id}: {doc.get('source')} can never fire ({codes})")
        line = (
            f"{pack_id}: {len(docs)} documents, {len(docs) - len(never) - len(degraded)} can-fire, "
            f"{len(degraded)} degraded, {len(never)} can-never-fire"
        )
        print(line)
        summary.append(f"- {line}")
        if degraded:
            reasons = ", ".join(f"{c}={n}" for c, n in sorted(reason_counts(degraded).items()))
            print(f"  warning: {len(degraded)} degraded document(s) ({reasons})")
    return errors


def report_preview(engine: Path, preview: Path, only: str | None, summary: list[str]) -> None:
    for platform in PLATFORMS:
        rules = preview / platform
        if (only is not None and platform != only) or not rules.is_dir():
            continue
        try:
            report = run_doctor(engine, platform, rules)
        except RuntimeError as exc:
            print(f"preview/{platform}: sigma doctor could not report ({exc})")
            continue
        for doc in report["documents"]:
            verdict = verdict_of(doc)
            reasons = ", ".join(r.get("code", "?") for r in doc.get("reasons", []))
            name = f"preview/{platform}/{doc.get('source')}"
            if verdict == "can-never-fire":
                print(f"preview: {name} still cannot fire ({reasons})")
                continue
            line = f"{name} is now {verdict}: promotion candidate"
            print(f"preview: {line}")
            summary.append(f"- {line}")
            if os.environ.get("GITHUB_ACTIONS"):
                print(f"::notice title=Preview promotion candidate::{line}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine", type=Path, required=True, help="path to the rustinel binary")
    parser.add_argument("--dist", type=Path, default=lib.REPO_ROOT / "dist")
    parser.add_argument("--preview", type=Path, default=lib.REPO_ROOT / "preview" / "sigma")
    parser.add_argument("--platform", choices=PLATFORMS, help="only packs for this platform")
    args = parser.parse_args()

    if not args.engine.exists():
        print(f"[ERROR] engine binary not found: {args.engine}", file=sys.stderr)
        return 1
    targets = production_targets(args.dist, args.platform)
    if not targets:
        print(
            f"[ERROR] no built packs under {args.dist}; run tools/build_packs.py", file=sys.stderr
        )
        return 1

    summary: list[str] = ["### sigma doctor"]
    errors = check_production(args.engine, targets, summary)
    report_preview(args.engine, args.preview, args.platform, summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write("\n".join(summary) + "\n")
    for error in errors:
        print(f"[ERROR] {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
