"""Discover and run the replay suites with the pinned Rustinel engine."""

import argparse
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from time import perf_counter

SUITE_DIR = Path(__file__).resolve().parent
MAIN_GUARD = re.compile(r"""^if __name__\s*==\s*(['"])__main__\1\s*:""", re.MULTILINE)


def discover_suites(directory: Path, platform: str) -> list[Path]:
    suites = []
    for path in sorted(directory.glob("*.py")):
        if path.name == "run_all.py" or path.name.startswith("_"):
            continue
        suite_platform = "macos" if path.name == "macos_detection_logic.py" else "linux"
        if platform in ("all", suite_platform) and MAIN_GUARD.search(
            path.read_text(encoding="utf-8")
        ):
            suites.append(path)
    return suites


def run_suite(suite: Path, engine: Path) -> tuple[int, float, str]:
    start = perf_counter()
    try:
        result = subprocess.run(
            [sys.executable, str(suite), "--engine", str(engine)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError as exc:
        return 1, perf_counter() - start, str(exc)
    return result.returncode, perf_counter() - start, result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path, help="path to the Rustinel binary")
    parser.add_argument("--platform", choices=("linux", "macos", "all"), default="all")
    parser.add_argument("--workers", type=int, default=4, help="parallel suites (default: 4)")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    engine = args.engine.resolve()
    if not engine.is_file():
        parser.error(f"engine binary not found: {engine}")
    suites = discover_suites(SUITE_DIR, args.platform)
    if not suites:
        parser.error(f"no replay suites found for {args.platform}")

    failures = []
    start = perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        running = {pool.submit(run_suite, suite, engine): suite.name for suite in suites}
        for future in as_completed(running):
            name = running[future]
            status, elapsed, output = future.result()
            label = "FAIL" if status else "PASS"
            print(f"[{label}] {name} ({elapsed:.2f}s)", flush=True)
            if status:
                failures.append((name, status, output))

    for name, status, output in sorted(failures):
        print(f"\n{name} exited with status {status}")
        if output:
            print(output.rstrip())
    elapsed = perf_counter() - start
    passed = len(suites) - len(failures)
    print(f"\nReplay suites: {passed} passed, {len(failures)} failed ({elapsed:.2f}s)")
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
