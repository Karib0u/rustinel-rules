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
  and what would unblock it - see [preview content](preview/README.md).
- **Quality is visible in CI.** If it isn't validated, it isn't trusted.

## Local setup

Tooling is managed with [uv](https://docs.astral.sh/uv/). One-time install of the pinned
dependencies (PyYAML, `jsonschema`, `yara-x`) and dev tools (`ruff`, `ty`):

```bash
uv sync --frozen
```

Then run the same checks CI runs:

```bash
uv run ruff check tools tests/replay
uv run ruff format --check tools tests/replay
uv run ty check
uv run python -m unittest discover -s tests/atomic -p 'test_*.py'
uv run python -m unittest discover -s tests/tools -p 'test_*.py'
uv run python tools/validate.py
```

## Adding a rule

1. Place the rule in the canonical source tree:
   - Sigma → `rules/sigma/<os>/`
   - YARA → `rules/yara/<os>/`
2. Give it a **stable, unique `id`** (UUID v4 for Sigma; `meta.id` for YARA, falling back to the rule name).
3. Include required metadata (see below).
4. Reference the rule's `id` in the relevant `pack.yml` under `rules.has` (see [Packs and build outputs](#packs-and-build-outputs)).
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

Add these under a `rustinel:` key for compatibility validation and test coverage tracking:

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

4. Reference the set's `id` in the relevant `pack.yml` under `rules.has` (see [Packs and build outputs](#packs-and-build-outputs)).
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

Hunting packs set `active_response_eligible: false` in `pack.yml` (validation enforces it).
The flag is carried into the build index and catalog, so tooling can refuse to wire hunting
alerts to automated response. Rules that also ship in Advanced stay eligible through Advanced.

Packs are cumulative: don't re-list a rule in Advanced if it's already in Essential - Advanced
`extends` Essential.

## Testing detections

Rules marked `test_status: atomic` need a manifest entry for each platform whose packs include them.
Essential rules must declare a test status other than `none`; manual tests also require a `test_reason` explaining the limitation.
Run the coverage check before opening a PR:

```bash
uv run python tests/atomic/run_atomics.py --check-coverage --strict-essential
```

The [atomic harness](tests/atomic/README.md) tests real alerts on Linux, Windows, and macOS in CI.
Use [capture and replay](https://docs.rustinel.io/replay/) to iterate on event-based detections locally.

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

## Engine compatibility

Check [Sigma support](https://docs.rustinel.io/sigma/) and [field availability](https://docs.rustinel.io/field-availability/) before writing a rule.
The [vendored engine contract](compatibility/README.md) pins the engine used by validation and atomic CI.
Fields that the engine never populates cannot be used by shipped rules; keep blocked content in [preview/](preview/README.md).

Field requirements determine each pack's minimum engine version.
Use `rustinel.min_engine` for requirements that cannot be inferred from fields.
Correlation rules replace `logsource` and `detection` with `correlation`; every referenced rule must ship in the same pack and target the same platform.
The validator checks their fields, telemetry, references, and engine floor.

YARA rules should declare `id`, `attack`, and `telemetry = "file_scan"` in `meta`.
Validation compiles YARA with `yara-x`.

## Packs and build outputs

Use `rules.has.sigma`, `rules.has.yara`, or `rules.has.ioc` in a pack manifest to add canonical artifact IDs:

```yaml
rules:
  has:
    sigma:
      - 7f3a1c2e-4b5d-4e6f-8a90-1b2c3d4e5f60
```

See [the pack schema](schemas/pack.schema.json) for inheritance, inclusion, and exclusion options.
After membership or rule metadata changes, run `uv run python tools/sync_packs.py` to regenerate each pack's `attack_coverage` and `test_status` from its member rules. Validation rejects drift in either, and insufficient `requires_rustinel` floors.

```bash
uv run python tools/build_packs.py
uv run python tools/build_catalog.py
uv run python tools/check_engine_install.py
```

The build writes pack folders, versioned ZIP files, and `index.json` to `dist/`.
IOC sets become four flat files with source IDs preserved in comments.
`catalog.json` contains the richer website catalog; refresh the website snapshot with `npm run sync:rules` from the website checkout.

The install check validates catalog metadata, ZIP layout, and compatibility against the latest published catalog.
Published pack IDs must remain available, and release versions must increase.
Use `--baseline none` only for offline checks.

## Submitting a PR

Use a conventional title such as `feat(windows): detect suspicious task actions` or `fix(linux): reduce persistence false positives`.
Add an appropriate label: `detections` (rule content), `enhancement`, `bug`, `testing`, `performance`, `documentation`, `dependencies`, `refactor`, `ci`, or `chore`.
Use `breaking-change` for incompatible changes and `skip-changelog` for release preparation or changes with no release-note value.
[Changelog categories](.github/release.yml) use labels, not title prefixes.

## Preparing a release

1. Open a `chore(release)` PR and bump `[project].version` in `pyproject.toml`.
   This is the single version source for pack manifests, archives, and catalogs.
2. Add `.github/release-notes/<version>.md`, without the leading `v`.
   Start with `## Highlights` and write 3 to 5 user-visible changes.
   Include `## Upgrade notes` for compatibility floor changes, renamed detections, or configuration changes.
   Keep previous notes in place.
3. Run the local checks above and require validation and atomic CI to pass.
   Run `uv run python tools/check_engine_install.py --release` after building to check against the published release.
4. Label the preparation PR `skip-changelog`, review the highlights, and check labels on the included PRs.
5. After merging, tag the reviewed commit `v<version>` and push the tag.

The release workflow rejects missing or blank highlights and a tag that disagrees with the project version.
It publishes the reviewed highlights followed by GitHub's generated, categorized PR changelog and comparison link.
Breaking Changes takes priority over Performance, Features, Bug Fixes, Documentation, Dependencies, and Maintenance.
Uncategorized PRs appear under Other Changes.

Releases include pack ZIPs, `index.json`, `index.json.minisig`, and `catalog.json`.
The workflow signs the catalog with `RELEASE_MINISIGN_KEY` and verifies it against [release-minisign.pub](release-minisign.pub).
Keep this public key and any engine updater trust key aligned when rotating signing keys.
