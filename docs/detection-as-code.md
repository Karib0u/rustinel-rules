# Detection as Code

Detection as Code exists from day one but stays **lightweight for v1**. The goal is to make quality
visible through CI without blocking contribution on heavyweight infrastructure.

## Mandatory v1 checks

These run in CI on every push and pull request (`tools/validate.py`, then `tools/build_packs.py`):

| Check                              | Where                |
| ---------------------------------- | -------------------- |
| Lint + format (`ruff`)             | CI (`uv run ruff`)   |
| Type check (`ty`)                  | CI (`uv run ty`)     |
| Valid YAML                         | `validate.py`        |
| Valid Sigma structure              | `validate.py`        |
| YARA compiles (`yara-x`)           | `validate.py`        |
| Valid IOC set (schema)             | `validate.py`        |
| IOC value sanity (hash/ip/domain/regex) | `validate.py`   |
| Required metadata                  | `validate.py`        |
| Unique artifact IDs                | `validate.py`        |
| Source / license metadata          | `validate.py`        |
| ATT&CK tags when relevant          | `validate.py`        |
| Pack attack_coverage drift guard   | `validate.py`        |
| Rustinel telemetry compatibility   | `validate.py`        |
| Pack manifest validation (schema)  | `validate.py`        |
| Rule reference / extends integrity | `validate.py`        |
| Sigma load/compile validation      | `validate.py` (stub) †|
| Engine-ready packs + zip artifacts | `build_packs.py`     |
| Flattened IOC files (per type)     | `build_packs.py`     |
| Generated `index.json`             | `build_packs.py`     |

YARA content is compiled with **yara-x** (the same engine Rustinel embeds), so a rule that won't
load is a hard CI failure rather than a structural guess. If yara-x is not installed locally,
`validate.py` falls back to structural brace/condition checks and warns.

† Sigma load/compile validation is still structural. Once a Rustinel CLI is available in CI, replace
the structural stub with `rustinel compile <pack>` to get a true Sigma load/compile gate.

## Progressive / optional checks

Added incrementally as the project matures:

- Atomic firing tests — **implemented** (see [Firing tests](#firing-tests))
- Detection coverage reports
- Performance smoke tests
- Field mapping coverage
- False-positive feedback tracking
- Artifact checksums in releases (the build already emits `sha256` per zip in `index.json`)

## Dynamic testing policy

We do **not** require one full dynamic / end-to-end test per rule in v1. Dynamic tests start small:

| Pack level  | v1 requirement                                  |
| ----------- | ----------------------------------------------- |
| Essential   | Selected Atomic tests where they make sense     |
| Advanced    | Best-effort dynamic tests                       |
| Hunting     | No dynamic test requirement                     |

Priority: prove that the most important **Essential** detections work end to end.

## Firing tests

Beyond static validation, the repo ships **atomic firing tests** that prove a rule
actually fires against the real engine. The harness ([`tests/atomic/`](../tests/atomic/),
orchestrated by `run_atomics.py`) installs a released Rustinel engine on a real
runner, performs a small **safe** atomic action for each rule — the behaviour the
rule is meant to catch — and checks the engine wrote a matching alert.

```text
atomic action  ->  real OS telemetry (eBPF / ETW / ES)  ->  rustinel  ->  alert?
```

Run by [`.github/workflows/atomic.yml`](../.github/workflows/atomic.yml) on every
pull request:

| Platform | Sensor            | Gates CI?                                              |
| -------- | ----------------- | ----------------------------------------------------- |
| Linux    | eBPF              | yes                                                    |
| Windows  | ETW               | yes                                                    |
| macOS    | Endpoint Security | no — experimental, reports only (`continue-on-error`) |

The same workflow runs `run_atomics.py --check-coverage --strict-essential`, which
flags any rule marked `test_status: atomic` that lacks a test, plus Essential rules
still left untested. See [`tests/atomic/README.md`](../tests/atomic/README.md) for
how a test is judged and how to add one.

## TTP / Atomic / CTI strategy

The baseline is **TTP/Atomic-based**, not threat-feed-based. Each detection should map to:

- ATT&CK tactics
- ATT&CK techniques
- Rustinel telemetry
- reproducible behavior
- Atomic-style validation where possible

CTI is used to **prioritize** future additions, not to blindly import noisy feed content.