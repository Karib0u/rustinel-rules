<p align="center">
  <img src="docs/images/logo-rustinel.png" alt="Rustinel logo" width="220">
</p>

<h1 align="center">rustinel-rules</h1>

<p align="center">
  <b>Official, curated detection content for the Rustinel endpoint detection engine.</b><br>
  Ready-to-load <b>Sigma</b> · <b>YARA</b> · <b>IOC</b> packs — no glue, no conversion step.
</p>

<p align="center">
  <a href="https://github.com/Karib0u/rustinel-rules/actions/workflows/validate.yml"><img src="https://github.com/Karib0u/rustinel-rules/actions/workflows/validate.yml/badge.svg" alt="Validate"></a>
  <img src="https://img.shields.io/badge/detection--as--code-✓-ff8a3d?style=flat-square" alt="Detection as Code">
  <img src="https://img.shields.io/badge/content-Sigma%20·%20YARA%20·%20IOC-ff8a3d?style=flat-square" alt="Sigma · YARA · IOC">
  <a href="https://github.com/Karib0u/rustinel"><img src="https://img.shields.io/badge/engine-Rustinel-d97835?style=flat-square&logo=rust" alt="Engine: Rustinel"></a>
  <img src="https://img.shields.io/badge/license-DRL%201.1-ff8a3d?style=flat-square" alt="License: DRL 1.1">
</p>

<p align="center">
  <a href="https://github.com/Karib0u/rustinel">Rustinel engine</a> ·
  <a href="https://docs.rustinel.io/">Documentation</a> ·
  <a href="docs/packs.md">Pack catalog</a> ·
  <a href="https://github.com/Karib0u/rustinel-rules/releases/latest">Download packs</a>
</p>

This is the **trusted, versioned, and CI-tested** detection-content repository for Rustinel.

```text
rustinel        →  the engine that collects telemetry and evaluates rules
rustinel-rules  →  the Sigma / YARA / IOC packs it loads   (this repo)
```

Each detection lives **once** in `rules/`, carries a stable `id`, and is referenced from **packs** by that id. CI validates every change and builds flat, zipped packs plus an `index.json` catalog the engine can load directly.

---

## Load a pack in 60 seconds

> Need the engine first? Grab it from the **[Rustinel repo](https://github.com/Karib0u/rustinel)** — then come back here for real detections.

**1. Download** the pack for your OS plus `index.json` from the [latest release](https://github.com/Karib0u/rustinel-rules/releases/latest), and unzip it:

```bash
unzip windows-essential-0.2.0.zip
```

**2. Point** `config.toml` at the unzipped pack — a pack folder *is* the directory Rustinel loads:

```toml
[scanner]
sigma_rules_path = "windows-essential/sigma"
yara_rules_path  = "windows-essential/yara"

[ioc]
hashes_path      = "windows-essential/ioc/hashes.txt"
ips_path         = "windows-essential/ioc/ips.txt"
domains_path     = "windows-essential/ioc/domains.txt"
paths_regex_path = "windows-essential/ioc/paths_regex.txt"
```

**3. Confirm it works.** The Essential packs ship the **EICAR** test IOC set — drop a standard EICAR test file on disk and Rustinel raises an IOC alert in `logs/alerts.json.<date>`.

> Packs are **cumulative**, so load **one** pack, not several. The exact paths for every pack are in each pack's `engine` block in `index.json`. Full reference: **[docs/usage.md](docs/usage.md)**.

---

## Packs

Higher levels `extend` the one below, so rules are never duplicated:

```text
Essential  ⊂  Advanced  ⊂  Hunting
```

| Pack                  | Level     | Default | Description                                                          |
| --------------------- | --------- | :-----: | -------------------------------------------------------------------- |
| **Windows Essential** | essential |   ✅    | Low-noise, high-confidence Windows detections. Safe default.         |
| **Windows Advanced**  | advanced  |   ❌    | Essential + broader production detections. More FPs may occur.       |
| **Windows Hunting**   | hunting   |   ❌    | Advanced + broad/noisier hunting content for analysts.               |
| **Linux Essential**   | essential |   ✅    | Low-noise, high-confidence Linux detections. Safe default.           |
| **Linux Advanced**    | advanced  |   ❌    | Essential + broader Linux detections (persistence, exec).            |
| **macOS Essential**   | essential |   ❌    | _Experimental._ Keychain theft, Gatekeeper bypass, cryptominers.     |
| **macOS Advanced**    | advanced  |   ❌    | _Experimental._ Essential + launch-item persistence, cradles, exec.  |

> **macOS packs are experimental and post-v1** — not yet production-ready, so both ship `default: false`. See [docs/packs.md#macos](docs/packs.md#macos) for current limits.

Full catalog and per-pack rule inventory: **[docs/packs.md](docs/packs.md)**.

---

## Versioning & compatibility

`rustinel-rules` is versioned **independently** from the engine — detection content evolves faster. Each pack manifest declares the engine version it needs:

```yaml
pack_schema_version: 2
requires_rustinel: ">=1.0.2"
```

Release artifacts ship zip packs, `index.json`, compatibility metadata, and a `sha256` per artifact.

---

## Develop

Build and validate packs locally with the pinned tooling ([uv](https://docs.astral.sh/uv/)):

```bash
uv sync                                 # install pinned tooling
uv run python tools/validate.py         # Detection as Code: must pass
uv run python tools/build_packs.py      # build dist/<pack>/ + zips + index.json
uv run python tools/build_catalog.py    # build the website catalog (dist/catalog.json)
```

```text
rustinel-rules/
├── rules/            # Canonical source — each artifact exists ONCE
│   ├── sigma/<os>/   # Sigma rules (.yml)
│   ├── yara/<os>/    # YARA rules (.yar)
│   └── ioc/<os|common>/  # Typed IOC sets (hashes / ips / domains / paths_regex)
├── packs/            # Pack manifests — reference artifacts by id, never copy
├── schemas/          # JSON Schema for pack.yml and IOC sets (v1)
├── tools/            # Build + validation tooling
├── tests/atomic/     # Atomic firing tests — run the engine on real Linux/Windows/macOS runners
└── dist/             # Build output (gitignored): packs + zips + index.json
```

New detections should be TTP/Atomic-based, mapped to ATT&CK, and compatible with Rustinel telemetry. Start with **[docs/authoring.md](docs/authoring.md)** and **[CONTRIBUTING.md](CONTRIBUTING.md)**.

---

## Guiding principles

- Start small — a few proven detections beat many noisy ones.
- Keep Essential strict and low-FP; no noisy defaults.
- Each rule lives once; packs reference it by id.
- Keep Rustinel usable out of the box, with quality made visible through CI.
- Prefer TTP / telemetry-based curation; use CTI to **prioritize**, not to bulk-import.

---

## Documentation

| Doc | What's inside |
| --- | ------------- |
| **[docs/index.md](docs/index.md)** | Documentation map / start here |
| **[docs/usage.md](docs/usage.md)** | Installing packs and the `config.toml` reference |
| **[docs/packs.md](docs/packs.md)** | Pack catalog and the full rule inventory |
| **[docs/rustinel-support.md](docs/rustinel-support.md)** | What Rustinel supports: telemetry, fields, Sigma operators, YARA, IOC |
| **[docs/authoring.md](docs/authoring.md)** | Writing rules that load and fire on Rustinel |
| **[docs/repository.md](docs/repository.md)** | Artifact model, packs, and the build pipeline |
| **[docs/detection-as-code.md](docs/detection-as-code.md)** | CI checks and the dynamic-testing policy |

---

## License

See [LICENSE](LICENSE).
