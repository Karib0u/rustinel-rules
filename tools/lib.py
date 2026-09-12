"""Shared helpers for rustinel-rules tooling.

Loads the canonical detection sources — Sigma rules, YARA rules and IOC sets —
plus the pack manifests, and resolves the cumulative (`extends`) membership of
each pack.

Each detection artifact (Sigma rule, YARA rule, IOC set) lives **once** under
`rules/` and carries a stable `id`. Packs reference those ids and never copy
content. A pack materializes (see ``build_packs.py``) into exactly the layout the
Rustinel engine loads:

    sigma/         recursive dir of Sigma .yml      -> scanner.sigma_rules_path
    yara/          recursive dir of YARA .yar       -> scanner.yara_rules_path
    ioc/hashes.txt  ips.txt  domains.txt  paths_regex.txt
                                                    -> [ioc].*_path

Non-production content lives under `preview/` with the same layout and is loaded
only on request (``load_preview_artifacts``). Because pack resolution indexes the
`rules/` tree alone, a preview or test-only artifact can never end up in a built
pack; ``validate.py`` turns an attempted reference into a hard error.

Requires PyYAML (see tools/requirements.txt).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
PREVIEW_DIR = REPO_ROOT / "preview"
PREVIEW_REGISTER_PATH = PREVIEW_DIR / "preview.yml"
PACKS_DIR = REPO_ROOT / "packs"
SCHEMA_DIR = REPO_ROOT / "schemas"
PACK_SCHEMA_PATH = SCHEMA_DIR / "pack.schema.json"
IOC_SCHEMA_PATH = SCHEMA_DIR / "ioc.schema.json"
PREVIEW_SCHEMA_PATH = SCHEMA_DIR / "preview.schema.json"
DIST_DIR = REPO_ROOT / "dist"
# Test-only content is flattened here, deliberately outside dist/ so no release
# artifact can carry it. tests/atomic/run_atomics.py overlays it onto the staged
# pack at run time.
FIXTURES_DIR = REPO_ROOT / "build" / "fixtures"

# Canonical source globs, one per artifact kind.
SIGMA_GLOB = "sigma/**/*.yml"
YARA_GLOB = "yara/**/*.yar"
IOC_GLOB = "ioc/**/*.yml"

# IOC indicator types, in the order they are emitted. These map 1:1 onto the
# flat files the Rustinel `[ioc]` config consumes.
IOC_TYPES: tuple[str, ...] = ("hashes", "ips", "domains", "paths_regex")


class Artifact:
    """A single canonical detection source: a Sigma rule, YARA rule or IOC set.

    `kind` is one of "sigma" | "yara" | "ioc". `meta` holds the parsed document
    (Sigma/IOC) or extracted fields (YARA); `raw` is the original file text.
    """

    def __init__(self, artifact_id: str, kind: str, path: Path, meta: dict, raw: str):
        self.id = artifact_id
        self.kind = kind
        self.path = path
        self.meta = meta
        self.raw = raw

    @property
    def rel_path(self) -> str:
        return str(self.path.relative_to(REPO_ROOT))

    @property
    def indicators(self) -> dict[str, list[tuple[str, str | None]]]:
        """Normalized IOC indicators (empty for non-IOC artifacts)."""
        return parse_ioc_indicators(self.meta) if self.kind == "ioc" else {t: [] for t in IOC_TYPES}


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #


def load_sigma_rules(root: Path | None = None) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in sorted((root or RULES_DIR).glob(SIGMA_GLOB)):
        raw = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(raw) or {}
        rule_id = str(doc.get("id", "")).strip()
        artifacts.append(Artifact(rule_id, "sigma", path, doc, raw))
    return artifacts


_YARA_RULE_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)")
_YARA_META_ID_RE = re.compile(r'\bid\s*=\s*"([^"]+)"')
_YARA_META_ATTACK_RE = re.compile(r'\battack\s*=\s*"([^"]+)"')


def load_yara_rules(root: Path | None = None) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in sorted((root or RULES_DIR).glob(YARA_GLOB)):
        raw = path.read_text(encoding="utf-8")
        meta_id = _YARA_META_ID_RE.search(raw)
        name = _YARA_RULE_RE.search(raw)
        rule_id = (meta_id.group(1) if meta_id else name.group(1) if name else "").strip()
        meta = {"rule_name": name.group(1) if name else None}
        artifacts.append(Artifact(rule_id, "yara", path, meta, raw))
    return artifacts


def load_ioc_sets(root: Path | None = None) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in sorted((root or RULES_DIR).glob(IOC_GLOB)):
        raw = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(raw) or {}
        set_id = str(doc.get("id", "")).strip()
        artifacts.append(Artifact(set_id, "ioc", path, doc, raw))
    return artifacts


def load_all_artifacts(root: Path | None = None) -> list[Artifact]:
    """Every canonical artifact under `root` (default: the production rules/ tree).

    Pass PREVIEW_DIR to load non-production content. The two trees are never
    merged here: packs resolve against production artifacts only, which is what
    keeps preview and test-only content out of every built pack.
    """
    return load_sigma_rules(root) + load_yara_rules(root) + load_ioc_sets(root)


def load_preview_artifacts() -> list[Artifact]:
    return load_all_artifacts(PREVIEW_DIR) if PREVIEW_DIR.is_dir() else []


def load_preview_register() -> dict:
    """The preview/preview.yml register: why each non-production artifact is there."""
    if not PREVIEW_REGISTER_PATH.is_file():
        return {"schema": "rustinel-rules/preview@1", "entries": []}
    return yaml.safe_load(PREVIEW_REGISTER_PATH.read_text(encoding="utf-8")) or {}


def preview_entries_by_id() -> dict[str, dict]:
    return {
        str(entry.get("id")): entry
        for entry in (load_preview_register().get("entries") or [])
        if entry.get("id")
    }


def artifacts_by_id() -> dict[str, Artifact]:
    index: dict[str, Artifact] = {}
    for artifact in load_all_artifacts():
        if artifact.id:
            index[artifact.id] = artifact
    return index


# --------------------------------------------------------------------------- #
# IOC + ATT&CK helpers (shared by validate.py and build_packs.py)
# --------------------------------------------------------------------------- #


def parse_ioc_indicators(doc: dict) -> dict[str, list[tuple[str, str | None]]]:
    """Normalize an IOC set's `indicators` block into {type: [(value, comment)]}.

    Each entry may be a bare scalar (the value) or a mapping {value, comment}.
    Unknown indicator types are ignored here and flagged by validation.
    """
    result: dict[str, list[tuple[str, str | None]]] = {t: [] for t in IOC_TYPES}
    for ioc_type, entries in (doc.get("indicators") or {}).items():
        if ioc_type not in IOC_TYPES:
            continue
        for entry in entries or []:
            if isinstance(entry, dict):
                value = str(entry.get("value", "")).strip()
                comment = entry.get("comment")
                comment = str(comment).strip() if comment else None
            else:
                value = str(entry).strip()
                comment = None
            if value:
                result[ioc_type].append((value, comment))
    return result


_SIGMA_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def artifact_attack_techniques(artifact: Artifact) -> set:
    """Best-effort set of ATT&CK technique ids (e.g. {"T1059.001"}) declared by
    an artifact, used to detect pack attack_coverage drift."""
    techniques: set = set()
    if artifact.kind == "sigma":
        for tag in artifact.meta.get("tags") or []:
            match = _SIGMA_TECHNIQUE_RE.match(str(tag))
            if match:
                techniques.add(match.group(1).upper())
    elif artifact.kind == "yara":
        match = _YARA_META_ATTACK_RE.search(artifact.raw)
        if match:
            techniques.add(match.group(1).strip().upper())
    elif artifact.kind == "ioc":
        for technique in artifact.meta.get("attack") or []:
            techniques.add(str(technique).strip().upper())
    return techniques


# --------------------------------------------------------------------------- #
# Engine version requirements
# --------------------------------------------------------------------------- #

# The oldest engine any pack claims to support. Platform baselines raise this
# when the platform itself landed later; individual capabilities may raise it
# again below.
BASELINE_ENGINE = "1.0.2"

PLATFORM_BASELINE_ENGINES: dict[str, tuple[str, str]] = {
    "windows": (BASELINE_ENGINE, "Windows support is present at the v1.0.2 baseline"),
    "linux": (BASELINE_ENGINE, "Linux support is present at the v1.0.2 baseline"),
    "macos": (
        "1.1.0",
        "macOS process, file, network and DNS collection was introduced in v1.1.0",
    ),
}

# Capability -> the release that first provides it, as (platform, category,
# field, version, why).
#
# There is no machine-readable capability/version map in the engine repo: its
# compatibility/field-availability.json records what is available *now*, not
# since when. These entries come from the 2026-09-11 coverage audit's sensor
# inventory, which dated them against the release notes. Verify a new entry the
# same way before adding it, and prefer leaving a capability out to guessing —
# an over-claimed floor locks out engines that would have run the pack fine.
#
# Deliberately absent: file_delete / file_rename routing. It is present from the
# platform baseline onward (v1.0.2 on Linux, v1.1.0 on macOS), so it does not
# raise either platform's floor.
ENGINE_REQUIREMENTS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "windows",
        "registry_event",
        "Details",
        "1.4.0",
        "registry events began carrying value data in v1.4.0 (rustinel#310)",
    ),
    (
        "windows",
        "service_creation",
        "ImagePath",
        "1.4.1",
        "service_creation gained ImagePath / Provider_Name in v1.4.1",
    ),
    (
        "windows",
        "service_creation",
        "ServiceFileName",
        "1.4.1",
        "ServiceFileName resolves to the ImagePath added in v1.4.1",
    ),
    (
        "windows",
        "service_creation",
        "Provider_Name",
        "1.4.1",
        "service_creation gained ImagePath / Provider_Name in v1.4.1",
    ),
    (
        "windows",
        "process_creation",
        "IntegrityLevel",
        "1.4.1",
        "IntegrityLevel is populated from v1.4.1",
    ),
)

# Sub-categories that share a parent's field contract.
_CATEGORY_PARENTS = {
    "file_create": "file_event",
    "file_delete": "file_event",
    "file_rename": "file_event",
    "file_change": "file_event",
    "registry_add": "registry_event",
    "registry_set": "registry_event",
    "registry_delete": "registry_event",
    "dns": "dns_query",
}


def parse_version(version: str) -> tuple[int, ...]:
    """'1.4.10' -> (1, 4, 10). Used only to order the versions in this repo."""
    parts = []
    for chunk in str(version).strip().lstrip("v").split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def max_version(*versions: str) -> str:
    return max(versions, key=parse_version)


def constraint_floor(constraint: str) -> str | None:
    """The version in a '>=X.Y.Z' constraint, or None if it isn't that shape."""
    text = str(constraint or "").strip()
    if not text.startswith(">="):
        return None
    return text[2:].strip().lstrip("v") or None


def platform_baseline_engine(platform: str) -> tuple[str, str | None]:
    """Return the first engine release supporting a platform and the reason."""
    requirement = PLATFORM_BASELINE_ENGINES.get(str(platform or "").lower())
    if requirement is None:
        return BASELINE_ENGINE, None
    return requirement


def detection_fields(detection: dict) -> set[str]:
    """Every field name a Sigma rule's selections reference, modifiers stripped."""
    fields: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                fields.add(str(key).split("|", 1)[0])
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for name, selection in (detection or {}).items():
        if name in ("condition", "timeframe"):
            continue
        walk(selection)
    return fields


def artifact_min_engine(artifact: Artifact) -> tuple[str, list[str]]:
    """The oldest engine that can run this artifact, plus why it is not the baseline.

    A rule may also state `rustinel.min_engine` directly, for a requirement this
    table cannot see (a correlation rule needs v1.5.0 whatever its fields are).
    The declared value only ever raises the result.
    """
    minimum = BASELINE_ENGINE
    reasons: list[str] = []

    if artifact.kind == "sigma" and isinstance(artifact.meta, dict):
        logsource = artifact.meta.get("logsource") or {}
        product = str(logsource.get("product") or "").lower()
        platform_minimum, platform_reason = platform_baseline_engine(product)
        if parse_version(platform_minimum) > parse_version(minimum):
            minimum = platform_minimum
            if platform_reason:
                reasons.append(platform_reason)
        category = str(logsource.get("category") or "").lower()
        category = _CATEGORY_PARENTS.get(category, category)
        used = detection_fields(artifact.meta.get("detection") or {})

        for req_product, req_category, field, version, why in ENGINE_REQUIREMENTS:
            if req_product == product and req_category == category and field in used:
                if parse_version(version) > parse_version(minimum):
                    minimum = version
                reasons.append(f"{field}: {why}")

        declared = str((artifact.meta.get("rustinel") or {}).get("min_engine") or "").strip()
        if declared:
            if parse_version(declared) > parse_version(minimum):
                minimum = declared
            reasons.append(f"declared rustinel.min_engine: {declared}")

    return minimum, reasons


def pack_min_engine(
    resolved_ids, artifact_index, platform: str | None = None
) -> tuple[str, dict[str, list[str]]]:
    """A pack's floor: the newest engine any of its members needs."""
    minimum, _ = platform_baseline_engine(platform or "")
    drivers: dict[str, list[str]] = {}
    for artifact_id in resolved_ids:
        artifact = artifact_index.get(artifact_id)
        if artifact is None:
            continue
        rule_min, reasons = artifact_min_engine(artifact)
        if parse_version(rule_min) > parse_version(minimum):
            minimum = rule_min
        if reasons:
            drivers[artifact_id] = reasons
    return minimum, drivers


# --------------------------------------------------------------------------- #
# Packs
# --------------------------------------------------------------------------- #


def load_packs() -> list[dict]:
    packs: list[dict] = []
    for path in sorted(PACKS_DIR.glob("**/pack.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        doc["__path__"] = path
        packs.append(doc)
    return packs


def packs_by_id() -> dict[str, dict]:
    return {p["id"]: p for p in load_packs() if "id" in p}


def _get_rule_ids_from_dict(sub_dict: dict | list | None) -> list[str]:
    if not sub_dict:
        return []
    if isinstance(sub_dict, list):
        return [str(item) for item in sub_dict]
    ids = []
    for category in ("sigma", "yara", "ioc"):
        for item in sub_dict.get(category) or []:
            ids.append(str(item))
    return ids


def get_pack_subfolder_rules(pack: dict) -> dict[str, list[str]]:
    """Scan the pack's directories and return a dict of {category: [rule_ids]}."""
    result = {"sigma": [], "yara": [], "ioc": []}
    pack_path_str = pack.get("__path__")
    if not pack_path_str:
        return result
    pack_dir = Path(pack_path_str).parent

    # Build a map of filename to artifact ID from canonical rules
    filename_to_id = {}
    for art in load_all_artifacts():
        if art.id:
            filename_to_id[(art.kind, art.path.name)] = art.id

    # 1. Sigma
    sigma_dir = pack_dir / "sigma"
    if sigma_dir.is_dir():
        for file in sorted(sigma_dir.glob("*")):
            if file.is_file() and file.suffix in (".yml", ".yaml"):
                if ("sigma", file.name) in filename_to_id:
                    result["sigma"].append(filename_to_id[("sigma", file.name)])
                else:
                    try:
                        doc = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
                        rule_id = str(doc.get("id", "")).strip()
                        if rule_id:
                            result["sigma"].append(rule_id)
                    except Exception:
                        pass

    # 2. Yara
    yara_dir = pack_dir / "yara"
    if yara_dir.is_dir():
        for file in sorted(yara_dir.glob("*")):
            if file.is_file() and file.suffix in (".yar", ".yara"):
                if ("yara", file.name) in filename_to_id:
                    result["yara"].append(filename_to_id[("yara", file.name)])
                else:
                    try:
                        raw = file.read_text(encoding="utf-8")
                        meta_id = _YARA_META_ID_RE.search(raw)
                        name = _YARA_RULE_RE.search(raw)
                        rule_id = (
                            meta_id.group(1) if meta_id else name.group(1) if name else ""
                        ).strip()
                        if rule_id:
                            result["yara"].append(rule_id)
                    except Exception:
                        pass

    # 3. IOC
    ioc_dir = pack_dir / "ioc"
    if ioc_dir.is_dir():
        ioc_rule_ids = set()
        for file in ioc_dir.glob("*.txt"):
            try:
                content = file.read_text(encoding="utf-8")
                for match in re.finditer(r"\brule=([a-zA-Z0-9_-]+)", content):
                    ioc_rule_ids.add(match.group(1))
            except Exception:
                pass
        result["ioc"] = sorted(list(ioc_rule_ids))

    return result


def resolve_pack_rules(pack: dict, by_id: dict[str, dict]) -> list[str]:
    """Return the ordered, de-duplicated artifact ids for a pack, including all
    transitively extended packs. Lower-level packs come first.

    Applies the dictionary-based 'includes' and 'excludes' filtering.
    Authoritative rules are loaded from the pack's rules subfolder if present,
    otherwise falling back to 'has' under rules in the pack manifest.

    Raises ValueError on a missing extends target or an extends cycle.
    """

    def visit(pack_id: str, stack: list[str]) -> list[str]:
        if pack_id in stack:
            raise ValueError(f"extends cycle: {' -> '.join(stack + [pack_id])}")
        if pack_id not in by_id:
            raise ValueError(f"unknown pack in extends: {pack_id}")
        node = by_id[pack_id]

        # 1. Resolve parent rules recursively
        extended_rules = []
        extended_seen = set()
        for parent in node.get("extends", []) or []:
            parent_resolved = visit(parent, stack + [pack_id])
            for r in parent_resolved:
                if r not in extended_seen:
                    extended_seen.add(r)
                    extended_rules.append(r)

        # 2. Extract rules dictionary from manifest
        rules_dict = node.get("rules") or {}

        # If rules is a list (old format), treat it as 'has' list of rules
        if isinstance(rules_dict, list):
            has_dict_list = rules_dict
            includes_list = []
            excludes_list = []
        else:
            has_dict_list = _get_rule_ids_from_dict(rules_dict.get("has"))
            includes_list = _get_rule_ids_from_dict(rules_dict.get("includes"))
            excludes_list = _get_rule_ids_from_dict(rules_dict.get("excludes"))

        # 3. Filter extended rules using 'includes' and 'excludes'
        # If 'includes' key is specified (or rules is list, where we don't have includes),
        # filter extended rules to only those in the include list.
        if not isinstance(rules_dict, list) and "includes" in rules_dict:
            include_ids = set(includes_list)
            filtered_extended = [r for r in extended_rules if r in include_ids]
        else:
            filtered_extended = list(extended_rules)

        # If 'excludes' key is specified (or in rules), filter them out.
        exclude_ids = set(excludes_list)
        filtered_extended = [r for r in filtered_extended if r not in exclude_ids]

        # 4. Get 'has' rules.
        # Check subfolders (authoritative) first if any rules are there,
        # otherwise use manifest's 'has'.
        subfolder_rules = get_pack_subfolder_rules(node)
        sub_rule_ids = _get_rule_ids_from_dict(subfolder_rules)
        if sub_rule_ids:
            has_rules = sub_rule_ids
        else:
            has_rules = has_dict_list

        has_rules = [r for r in has_rules if r not in exclude_ids]

        # Combine everything
        combined = filtered_extended + has_rules

        # De-duplicate preserving order
        resolved = []
        seen = set()
        for r in combined:
            if r not in seen:
                seen.add(r)
                resolved.append(r)
        return resolved

    return visit(pack["id"], [])
