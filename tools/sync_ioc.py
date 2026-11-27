"""Shared snapshot and YAML handling for the pinned IOC sync scripts."""

import argparse
import json
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from io import StringIO
from pathlib import Path

import yaml
from ruamel.yaml import YAML

import lib

WARNINGLIST_PATH = lib.REPO_ROOT / "tools/ioc_warninglists.json"
LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def clean_text(value: str) -> str:
    return " ".join(value.replace(chr(0x2014), "-").split())


def read_records(source: Path) -> list[tuple[str, dict]]:
    """Read a directory of upstream YAML or a single YAML/JSON fixture."""
    paths = (
        sorted(path for path in source.iterdir() if path.suffix in {".yml", ".yaml"})
        if source.is_dir()
        else [source]
    )
    records = []
    for path in paths:
        data = yaml.load(path.read_bytes(), Loader=LOADER)
        for record in data if isinstance(data, list) else [data]:
            if not isinstance(record, dict):
                raise ValueError(f"{path}: expected an upstream record mapping")
            records.append((path.name, record))
    return records


def fetch_records(repository: str, revision: str) -> list[tuple[str, dict]]:
    """Fetch only the metadata directory from the exact upstream Git commit."""
    with tempfile.TemporaryDirectory(prefix="rustinel-ioc-") as directory:
        git = ["git", "-C", directory]
        for args in (
            ("init", "--quiet"),
            ("remote", "add", "origin", repository + ".git"),
            ("fetch", "--quiet", "--depth=1", "--filter=blob:none", "origin", revision),
            ("sparse-checkout", "set", "--no-cone", "/yaml/*.yaml", "/yaml/*.yml"),
            ("checkout", "--quiet", "--detach", revision),
        ):
            subprocess.run([*git, *args], check=True, timeout=120)
        return read_records(Path(directory) / "yaml")


def render(
    current: str, repository: str, revision: str, kind: str, entries: list[dict[str, str]]
) -> str:
    """Regenerate indicators and pinned references while preserving rule metadata."""
    yaml_rt = YAML()
    yaml_rt.preserve_quotes = True
    yaml_rt.indent(mapping=2, sequence=4, offset=2)
    # Keep generated attribution on one line, including for shared indicators.
    yaml_rt.width = 4096
    document = yaml_rt.load(current)
    references = [
        f"{repository}/tree/{revision}/yaml",
        f"{repository}/blob/{revision}/LICENSE",
    ]
    references.extend(
        ref for ref in document.get("references", []) if not ref.startswith(repository)
    )
    document["references"] = references
    document["indicators"] = {kind: entries}
    output = StringIO()
    yaml_rt.dump(document, output)
    return output.getvalue()


def sync(
    description: str,
    repository: str,
    revision: str,
    output: Path,
    kind: str,
    collect: Callable[[list[tuple[str, dict]], dict], list[dict[str, str]]],
    argv: Sequence[str] | None,
) -> int:
    parser = argparse.ArgumentParser(description=description)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="regenerate the IOC set")
    mode.add_argument("--check", action="store_true", help="exit 1 if the IOC set is stale")
    parser.add_argument("--input", type=Path, help="read local YAML records or a YAML/JSON fixture")
    args = parser.parse_args(argv)

    records = read_records(args.input) if args.input else fetch_records(repository, revision)
    warninglists = json.loads(WARNINGLIST_PATH.read_text(encoding="utf-8"))
    entries = collect(records, warninglists)
    if not entries:
        parser.error("no indicators survived filtering")
    current = output.read_text(encoding="utf-8")
    generated = render(current, repository, revision, kind, entries)
    if args.check and generated != current:
        print(f"[STALE] {output}")
        return 1
    if args.write and generated != current:
        output.write_text(generated, encoding="utf-8")
    print(f"[OK] {output.name}: {len(entries)} {kind} from {revision}")
    return 0
