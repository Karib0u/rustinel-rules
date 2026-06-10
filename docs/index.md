# rustinel-rules documentation

Detection content for the [Rustinel](https://github.com/Karib0u/rustinel) endpoint detection
engine. This repository holds curated **Sigma**, **YARA** and **IOC** detections, organizes them
into cumulative **packs**, validates them in CI, and builds flat artifacts the engine loads
directly.

## Start here

New to the repo? Read these in order:

1. **[Repository model](repository.md)** — how detections, packs and the build pipeline fit together.
2. **[Packs](packs.md)** — the catalog of packs and every rule they contain.
3. **[Using packs with Rustinel](usage.md)** — install a pack and wire `config.toml`.

## Reference

- **[Rustinel support reference](rustinel-support.md)** — the authoritative list of what the engine
  can detect: telemetry channels, Sigma log sources and fields, supported Sigma operators/modifiers,
  YARA behavior, and IOC types/formats. **Read this before writing a rule** — anything outside it
  won't load or fire.
- **[Authoring rules](authoring.md)** — step-by-step for adding Sigma, YARA and IOC content.
- **[Detection as Code](detection-as-code.md)** — the CI checks and the dynamic-testing policy.

## At a glance

| Concept | Summary |
| ------- | ------- |
| **Artifact** | One detection (Sigma rule, YARA rule, or IOC set). Lives once under `rules/`, has a stable `id`. |
| **Pack** | A manifest (`packs/<os>/<level>/pack.yml`) listing artifact ids. Packs are cumulative via `extends`. |
| **Level** | `essential` (safe default) ⊂ `advanced` ⊂ `hunting` (analyst-driven, noisy). |
| **Build** | `tools/build_packs.py` materializes each pack into a flat, zipped folder + `index.json`. |
| **Validation** | `tools/validate.py` enforces metadata, unique ids, ATT&CK tags, Rustinel telemetry compatibility, IOC sanity. |

## Tooling commands

```bash
uv sync                                 # one-time: install pinned tooling into .venv
uv run python tools/validate.py         # Detection-as-Code checks (run before every PR)
uv run python tools/build_packs.py      # Materialize packs into dist/ (folders + zips + index.json)
```

Tooling is managed with [uv](https://docs.astral.sh/uv/): dependencies (PyYAML,
`jsonschema`, `yara-x`) and dev tools (`ruff`, `ty`) are pinned in
[`pyproject.toml`](../pyproject.toml) / `uv.lock`. Lint, format and type-check with:

```bash
uv run ruff check tools         # lint
uv run ruff format tools        # format
uv run ty check                 # type-check
```
