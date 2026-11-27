"""Load atomic test definitions for the harness and detection validator."""

import json
from pathlib import Path


def load_manifest(path: Path) -> list[dict]:
    """Read one manifest file or recursively merge a directory in path order."""
    files = sorted(path.rglob("*.json"), key=Path.as_posix) if path.is_dir() else [path]
    if not files:
        raise ValueError(f"{path}: no JSON manifests found")

    tests: list[dict] = []
    names: dict[str, str] = {}
    ids: dict[tuple[str, str, str], str] = {}
    for file in files:
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{file}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("tests"), list):
            raise ValueError(f"{file}: expected a 'tests' array")

        for index, test in enumerate(data["tests"], start=1):
            where = f"{file} (test {index})"
            if not isinstance(test, dict) or not all(
                isinstance(test.get(field), str) and test[field].strip()
                for field in ("name", "id", "platform")
            ):
                raise ValueError(f"{where}: expected non-empty name, id, and platform strings")
            name, rule_id, platform = test["name"], test["id"], test["platform"]
            variant = test.get("variant", "")
            if "variant" in test and (not isinstance(variant, str) or not variant.strip()):
                raise ValueError(f"{where}: {name} has an empty or invalid variant")

            if name in names:
                raise ValueError(f"{where}: duplicate test name {name!r} (also in {names[name]})")
            key = (platform, rule_id, variant)
            if key in ids:
                case = f" (variant {variant!r})" if variant else ""
                raise ValueError(
                    f"{where}: duplicate rule ID {rule_id!r} on {platform}{case} "
                    f"(also in {ids[key]})"
                )

            # A test that may miss, or does not run, must say why.
            if test.get("allow_failure") and not test.get("allow_failure_reason"):
                raise ValueError(f"{where}: {name} sets allow_failure without allow_failure_reason")
            if "skip" in test and not str(test["skip"]).strip():
                raise ValueError(f"{where}: {name} has an empty skip reason")

            names[name] = ids[key] = where
            tests.append(test)
    return tests
