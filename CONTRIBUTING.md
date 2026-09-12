# Contributing to rustinel-rules

Thanks for helping improve Rustinel detection content. This repository optimizes for **defenders and
maintainers**: high-confidence, low-noise, reproducible detections that are mapped to known
adversary behavior.

## Principles

- **Start small.** Prefer a few proven detections over many noisy ones.
- **TTP/Atomic-based baseline.** Map detections to ATT&CK tactics + techniques and, where possible,
  to a reproducible Atomic-style test.
- **CTI prioritizes, it does not import.** Threat intel helps decide *what to build next*, not to
  bulk-import noisy feed content.
- **No duplicated rules.** Each rule lives once in `rules/`; packs reference it by `id`.
- **A rule that cannot fire does not ship.** If a selection needs a field Rustinel never
  populates, the rule goes under `preview/` with an entry in `preview/preview.yml` saying why
  and what would unblock it — see [authoring](docs/authoring.md#when-a-rule-cant-ship-preview).
- **Quality is visible in CI.** If it isn't validated, it isn't trusted.

## Local setup

Tooling is managed with [uv](https://docs.astral.sh/uv/). One-time install of the pinned
dependencies (PyYAML, `jsonschema`, `yara-x`) and dev tools (`ruff`, `ty`):

```bash
uv sync
```

Then run the same checks CI runs:

```bash
uv run ruff check tools         # lint
uv run ruff format --check tools  # format
uv run ty check                 # type-check
uv run python tools/validate.py # Detection-as-Code (includes yara-x compile gate)
```

## Adding a rule

1. Place the rule in the canonical source tree:
   - Sigma → `rules/sigma/<os>/`
   - YARA → `rules/yara/<os>/`
2. Give it a **stable, unique `id`** (UUID v4 for Sigma; a unique rule name for YARA).
3. Include required metadata (see below).
4. Reference the rule's `id` from the relevant `pack.yml` `rules:` list.
5. Run `uv run python tools/validate.py` locally.

### Required Sigma metadata

| Field                | Notes                                                       |
| -------------------- | ----------------------------------------------------------- |
| `title`              | Short, descriptive                                          |
| `id`                 | UUID v4, unique across the repo                             |
| `status`             | `experimental` \| `test` \| `stable`                        |
| `description`        | What it detects and why                                     |
| `references`         | Source/CTI links                                            |
| `author`             | Attribution                                                 |
| `level`              | `informational` \| `low` \| `medium` \| `high` \| `critical`|
| `tags`               | ATT&CK tags, e.g. `attack.execution`, `attack.t1059.001`    |
| `logsource`          | Must map to a Rustinel-supported telemetry source           |
| `detection`          | Valid Sigma detection logic                                 |

### Custom metadata (Rustinel-specific)

Add these under a `rustinel:` key so they survive validation and reach `index.json`:

```yaml
rustinel:
  telemetry: [process_creation]      # Rustinel telemetry channels required
  expected_false_positive_level: low # low | medium | high
  test_status: atomic                # none | atomic | manual | dynamic
```

## Adding an IOC set

IOCs are stored as **typed sets**, not one file per indicator. A set groups
related indicators (a campaign, a tool, an infrastructure cluster) and is the unit
packs reference by `id`.

1. Place the set under `rules/ioc/<os|common>/<name>.yml` (use `common` for
   cross-platform indicators).
2. Give it a stable `id` prefixed with `ioc-` (e.g. `ioc-cobaltstrike-2026q2`).
3. Add indicators under the relevant type(s). Each entry is either a bare value or
   a `{value, comment}` map:

   ```yaml
   id: ioc-example-campaign
   description: What these indicators represent and where they came from.
   os: [windows, common]
   attack: [T1071.001]
   severity: high
   references:
     - https://...
   indicators:
     hashes:
       - value: 0c2674c3a97c53082187d930efb645c2
         comment: dropper sample
     domains:
       - "*.evil.example"        # leading "*." / "." matches subdomains
     ips:
       - 198.51.100.7            # single IP or CIDR
     paths_regex:
       - '^C:\\Users\\Public\\.*\.exe$'
   ```

4. Reference the set's `id` from the relevant `pack.yml` `rules:` list.
5. Run `uv run python tools/validate.py` (it checks hash/IP/domain/regex well-formedness).

The build flattens every referenced set into the four files Rustinel's `[ioc]`
config loads (`hashes.txt`, `ips.txt`, `domains.txt`, `paths_regex.txt`), tagging
each line with its source set id for provenance.

## Choosing a pack level

| Level       | Bar for inclusion                                                            |
| ----------- | --------------------------------------------------------------------------- |
| `essential` | High-confidence, low-FP, broadly applicable. Safe to enable by default.     |
| `advanced`  | Solid production value; may produce environment-dependent false positives.  |
| `hunting`   | Broad/noisy leads for analysts. Never enabled by default.                   |

Packs are cumulative: don't re-list a rule in Advanced if it's already in Essential — Advanced
`extends` Essential.

## Dynamic testing policy (v1)

We do **not** require a full dynamic/end-to-end test per rule in v1.

- **Essential:** selected Atomic tests where they make sense.
- **Advanced:** best-effort dynamic tests.
- **Hunting:** no dynamic test requirement for v1.

Priority: prove that the most important **Essential** detections work end to end.

## False positives

FP rates are environment- and org-dependent; we don't define a universal rate. Instead:

- Document `expected_false_positive_level` per rule/pack.
- Track community feedback via GitHub issues.
- Mark known-noisy rules.
- Keep Essential strict and low-noise.

## Before opening a PR

```bash
uv run python tools/validate.py     # must pass
uv run python tools/build_packs.py  # should produce dist/ artifacts cleanly
```