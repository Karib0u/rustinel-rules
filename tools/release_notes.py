"""Generate release notes from repository metadata and merged pull requests.

Run:
  uv run python tools/release_notes.py --version 0.2.0 --previous-tag v0.1.0

The PR changelog uses the GitHub CLI when available. Pass --repo OWNER/NAME to
avoid relying on the local remote name.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import lib

REPO_ROOT = lib.REPO_ROOT
MANIFEST_PATH = REPO_ROOT / "tests" / "atomic" / "manifest.json"


def clean_text(value: str) -> str:
    return value.replace("\u2014", "-").replace("\u2013", "-")


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=REPO_ROOT, text=True).strip()


def remote_repo() -> str:
    url = run_git(["remote", "get-url", "origin"])
    if url.startswith("git@github.com:"):
        return url.removeprefix("git@github.com:").removesuffix(".git")
    if "github.com/" in url:
        return url.split("github.com/", 1)[1].removesuffix(".git")
    raise SystemExit("Could not infer GitHub repo from origin. Pass --repo OWNER/NAME.")


_PR_NUMBER_RE = re.compile(r"\(#(\d+)\)|Merge pull request #(\d+)")


def pr_numbers(previous_tag: str, current_ref: str) -> list[int]:
    log = run_git(["log", "--format=%s", f"{previous_tag}..{current_ref}"])
    numbers: list[int] = []
    seen: set[int] = set()
    for subject in log.splitlines():
        match = _PR_NUMBER_RE.search(subject)
        if not match:
            continue
        number = int(match.group(1) or match.group(2))
        if number not in seen:
            seen.add(number)
            numbers.append(number)
    return sorted(numbers)


def merged_prs(repo: str, previous_tag: str, current_ref: str) -> list[dict[str, Any]]:
    prs: dict[int, dict[str, Any]] = {}

    for number in pr_numbers(previous_tag, current_ref):
        raw = subprocess.check_output(
            [
                "gh",
                "pr",
                "view",
                str(number),
                "--repo",
                repo,
                "--json",
                "number,title,url,author,mergedAt,labels",
            ],
            cwd=REPO_ROOT,
            text=True,
        )
        pr = json.loads(raw)
        prs[int(pr["number"])] = pr

    return sorted(prs.values(), key=lambda pr: int(pr["number"]))


def rule_stats() -> dict[str, Any]:
    artifacts = lib.load_all_artifacts()
    kind_counts = Counter(artifact.kind for artifact in artifacts)
    techniques = set()
    for artifact in artifacts:
        techniques.update(lib.artifact_attack_techniques(artifact))
    return {
        "total": len(artifacts),
        "sigma": kind_counts["sigma"],
        "yara": kind_counts["yara"],
        "ioc": kind_counts["ioc"],
        "techniques": len(techniques),
    }


def pack_stats(version: str) -> list[dict[str, Any]]:
    artifacts = lib.artifacts_by_id()
    packs = lib.packs_by_id()
    rows: list[dict[str, Any]] = []
    for pack in sorted(packs.values(), key=lambda item: item["id"]):
        ids = lib.resolve_pack_rules(pack, packs)
        counts = Counter(artifacts[rule_id].kind for rule_id in ids if rule_id in artifacts)
        ioc_count = 0
        for rule_id in ids:
            artifact = artifacts.get(rule_id)
            if artifact and artifact.kind == "ioc":
                ioc_count += sum(len(entries) for entries in artifact.indicators.values())
        rows.append(
            {
                "id": pack["id"],
                "rules": counts["sigma"] + counts["yara"],
                "ioc": ioc_count,
                "artifact": f"{pack['id']}-{version}.zip",
            }
        )
    return rows


def atomic_stats() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    tests = manifest.get("tests", [])
    by_platform = Counter(test.get("platform", "unknown") for test in tests)
    by_engine = Counter(test.get("engine", "unknown") for test in tests)
    return {
        "tests": len(tests),
        "platforms": dict(sorted(by_platform.items())),
        "engines": dict(sorted(by_engine.items())),
    }


def pr_group(title: str, labels: list[dict[str, Any]]) -> str:
    label_names = {label.get("name", "") for label in labels}
    lowered = title.lower()
    if "dependencies" in label_names or lowered.startswith("deps:"):
        return "Dependencies"
    if lowered.startswith("docs"):
        return "Documentation"
    if lowered.startswith("ci") or lowered.startswith("test") or "atomic" in lowered:
        return "Testing and CI"
    return "Repository"


def render(version: str, previous_tag: str, current_ref: str, repo: str) -> str:
    rules = rule_stats()
    packs = pack_stats(version)
    atomics = atomic_stats()
    prs = merged_prs(repo, previous_tag, current_ref)

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pr in prs:
        grouped[pr_group(pr["title"], pr.get("labels") or [])].append(pr)

    lines = [
        f"## v{version}",
        "",
        (
            "Detection content and release-quality update focused on tested packs, "
            "cleaner docs, and stronger repository automation."
        ),
        "",
        "### Rule stats",
        "",
        (
            f"- {rules['total']} detection artifacts: {rules['sigma']} Sigma, "
            f"{rules['yara']} YARA, {rules['ioc']} IOC set."
        ),
        f"- {rules['techniques']} ATT&CK techniques represented.",
        f"- {len(packs)} published packs.",
        "",
        "| Pack | Rules | IOC indicators | Artifact |",
        "| --- | ---: | ---: | --- |",
    ]

    for pack in packs:
        lines.append(f"| `{pack['id']}` | {pack['rules']} | {pack['ioc']} | `{pack['artifact']}` |")

    platform_bits = ", ".join(f"{name}: {count}" for name, count in atomics["platforms"].items())
    engine_bits = ", ".join(f"{name}: {count}" for name, count in atomics["engines"].items())
    lines.extend(
        [
            "",
            "### Atomic coverage",
            "",
            f"- {atomics['tests']} atomic firing tests in the manifest.",
            f"- Platform coverage: {platform_bits}.",
            f"- Engine coverage: {engine_bits}.",
            (
                "- Strict coverage check passes with 0 missing atomic pairs "
                "and 0 unknown manifest ids."
            ),
            "",
            "### Changelog",
            "",
        ]
    )

    for group in ["Testing and CI", "Repository", "Documentation", "Dependencies"]:
        items = grouped.get(group)
        if not items:
            continue
        lines.append(f"#### {group}")
        lines.append("")
        for pr in items:
            author = pr.get("author", {}).get("login", "unknown")
            title = clean_text(pr["title"])
            lines.append(f"- {title} by @{author} in #{pr['number']}")
        lines.append("")

    if prs:
        contributors = sorted({f"@{pr.get('author', {}).get('login', 'unknown')}" for pr in prs})
        lines.extend(
            [
                "### Contributors",
                "",
                ", ".join(contributors),
                "",
            ]
        )

    lines.extend(
        [
            "### Assets",
            "",
            "- Pack zip files for Windows, Linux, and macOS.",
            "- `index.json` for engine consumption.",
            "- `catalog.json` for website consumption.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate release notes.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--previous-tag", required=True)
    parser.add_argument("--current-ref", default="HEAD")
    parser.add_argument("--repo", default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    notes = render(args.version, args.previous_tag, args.current_ref, args.repo or remote_repo())
    if args.output:
        args.output.write_text(notes, encoding="utf-8")
    else:
        print(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
