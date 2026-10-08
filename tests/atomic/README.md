# Atomic firing tests

Real-condition firing tests for the detection content in this repo.

`tools/validate.py` proves a rule is *well-formed*. These tests prove it
*actually fires*: they install the [rustinel](https://github.com/Karib0u/rustinel)
engine on real **Windows**, **Linux** and **macOS** runners, perform a small safe
*atomic action* for each rule (the behaviour the rule is meant to catch), and
verify the engine raised an alert.

```text
atomic action  ->  real OS telemetry (eBPF / ETW / ES)  ->  rustinel  ->  alert?
   (a script)        (process / file / registry)            (engine)     (we check)
```

> **Status:** CI installs the released **v1.9.1** binaries on all three
> platforms. Linux, Windows and hosted `macos-latest` jobs all gate CI.
> Endpoint Security initialises under `sudo` with the released macOS binary.
> macOS packs remain disabled by default for users; CI loads them explicitly.

## Shared suite and engine pin

The workflow installs the released version recorded in
[`compatibility/engine.json`](../../compatibility/engine.json) (**1.9.1**), using
install scripts from the same exact commit as the vendored field contract, so an
unchanged rules revision keeps testing against the same engine release. The
first baseline was v1.6.0, the first release on which the full suite passed
across Linux, Windows and hosted macOS, including the IOC and WMI paths (see
[#37](https://github.com/Karib0u/rustinel-rules/issues/37)). The pin moved to
v1.8.0 in [#72](https://github.com/Karib0u/rustinel-rules/issues/72) to unblock
its Security, process-identity, hash and container telemetry; the full suite
passed on it on all three platforms. It then moved to v1.9.1, which brings the
schema 3 field contract.
The test pin is separate from each pack's content-derived `requires_rustinel`
minimum; passing here does not certify every older supported engine version.

The same suite has two uses:

- **Rules changes against a released engine:** this repository's CI builds the
  candidate rules and runs the full harness against the pinned released binary.
- **Engine changes against pinned rules:** the engine repository checks out an
  exact rules commit, builds its packs, and runs this harness with
  `--engine-bin` pointing at the candidate engine build. Keep the rules commit
  fixed when comparing engine changes. The report reads the actual binary's
  `--version`, including when testing a source build.

To deliberately update the engine pin:

1. Open a dedicated PR that refreshes the pin and field contract together with
   the [refresh procedure](../../compatibility/README.md), targeting an exact
   published release with binaries and installer scripts for all three
   platforms. Advance it when accepted content needs newer engine capabilities;
   keep the pin update separate from the content change.
2. Run the **full suite** on Linux, Windows and macOS with `pack: auto` and an
   empty filter (the normal PR run does this).
3. Review every failure, allowed failure, report and engine log against the
   previous baseline. Investigate regressions rather than weakening required
   tests to get a passing run.
4. Record the release choice and suite results in the PR, update this README's
   baseline, and merge only after all three gating jobs pass.

The Linux job also runs `tests/replay/linux_persistence.py` against the pinned
engine. These sensor-free replay cases check that containerd and dockerd writes
under their standard storage paths are excluded, while host persistence writes,
other writers, and missing writer metadata remain detectable. Custom storage
roots remain visible for explicit tuning. Run the same check locally with:

```bash
python3 tests/replay/linux_persistence.py --engine /path/to/rustinel
```

`tests/replay/linux_detection_logic.py` does the same for rule logic: each
corrected Linux rule (duplicate UID 0, `/dev/tcp`, netcat, kernel modules, chmod,
base64 pipelines, package-manager writers) has positive events and near-miss
negatives, so a loosened pattern fails before it reaches a sensor. These replays
run on hosted runners; real eBPF behaviour such as `O_APPEND` Modify events,
short-lived command-line enrichment and kernel module loading needs a controlled
host with BTF and is not exercised here.

```bash
python3 tests/replay/linux_detection_logic.py --engine /path/to/rustinel
```

`tests/replay/macos_detection_logic.py` is the macOS counterpart and runs in the
macOS job: the corrected Gatekeeper, quarantine, osascript, `/dev/tcp`, account,
launchctl, download-cradle, launch-item, `authorized_keys` and signing-aware
staging-execution rules each have positives and near-miss negatives, including
Apple platform and Team ID signed binaries that must not match. The engine
reports one alert per event, so each rule is replayed alone against its own
cases. Signing context is injected into the events, so this checks rule logic
only; real Endpoint Security signing values are exercised by the atomics.

```bash
python3 tests/replay/macos_detection_logic.py --engine /path/to/rustinel
```

`tests/replay/shell_history.py` guards the shell-history rules on both Linux and
macOS ([#43](https://github.com/Karib0u/rustinel-rules/issues/43)). The defect it
pins is the old `file_event` rule, which fired whenever an interactive shell saved
its history on exit. Each platform replays deletes, renames and in-place
destruction commands that must alert, next to the benign near misses that must
not: ordinary `.bash_history`/`.zsh_history` writes, zsh's temp-file rename *onto*
`.zsh_history`, `less`/`grep`/`tail` reads and `truncate`/`ln` on unrelated files.
The three rules sit on different event channels, so they cannot shadow each
other; the replay asserts the exact alert set. It runs in the Linux job for both
platforms:

```bash
python3 tests/replay/shell_history.py --engine /path/to/rustinel
```

Every job also runs `tools/sigma_doctor.py`, which asks the pinned engine's
`rustinel sigma doctor` whether each built pack for that platform can fire. It
fails on a parse or compile error and on any `can-never-fire` production rule;
`degraded` documents only warn (summarised by reason). `preview/` is report-only:
a Preview rule whose verdict improves is listed as a promotion candidate, never
promoted automatically. Run it locally after `tools/build_packs.py`:

```bash
uv run python tools/sigma_doctor.py --engine /path/to/rustinel
```

A latest-engine nightly job and a broader positive/negative certification corpus
are deferred.

---

## How a test is judged

The engine writes alerts as ECS NDJSON to `logs/alerts.json.<date>`. A test
**passes** when a new alert appears whose join key matches the rule:

| Engine | Join key the runner checks |
| --- | --- |
| Sigma / YARA | `rule.name` equals the rule's **title** (resolved by `id` from `rules/`) |
| IOC / custom | an explicit `expect: {field, contains}` (IOC alerts use `rule.name = "ioc:<kind>:<indicator>"`, so the canary matches on `rule.description ~ "canary-exec-hash"`) |

Most rules are *behavioural* (they match a process command line, a file path, a
registry key), so the atomic actions are **safe simulations** - a reverse-shell
command line aimed at a closed local port, `powershell -EncodedCommand` running a
benign `Write-Host`, a cron file containing `true`, an HKCU Run value pointing at
notepad. Nothing malicious executes; the telemetry is what trips the rule.

The IOC/file-hash path is the one that needs a real artifact. Rustinel hashes an
executable when it becomes a **process image**, so the canary atomic writes a
deterministic do-nothing executable - generated by `canary/make_canary.py`,
embedded in the script as base64 - and launches it. Its SHA-256 is the indicator.
(This replaced an EICAR test that could never pass: a file that is written but
never executed is never hashed, and EICAR cannot become a process image at all.)

---

## Detector-path smoke coverage

Each detector path has at least one firing test in this suite. Production
rules exercise Sigma and file-scan YARA; the paths production content has no
suitable trigger for use test-only fixtures from `preview/`:

| Path | Test | Trigger |
| --- | --- | --- |
| Sigma | the per-rule atomics | behavioural |
| Sigma correlation | `<os>_sigma_correlation_fixture` | an `event_count` correlation (>= 2 in 2m) over a marker rule; the atomic starts the marker process twice |
| IOC hash | `<os>_canary_ioc` (Linux, Windows) | executes the deterministic canary executable |
| IOC path | `macos_canary_ioc` | launches a binary from the canary path |
| IOC IP, domain | `<os>_canary_ioc_ip`, `<os>_canary_ioc_domain` | a short-lived process whose command line carries a TEST-NET-3 URL and a `.invalid` URL (no network) |
| YARA (disk) | `<os>_*_yara_fixture` | executable carrying the rule's marker strings |
| YARA (memory) | `<os>_yara_memory_fixture` | a long-lived process assembles a marker at runtime; only a process-memory scan sees it. The harness sets `scanner.yara_memory_enabled = true` |

macOS memory scanning and the macOS coinminer file scan are `allow_failure`
with a recorded reason until they have a track record on hosted runners.

The fixtures live under `preview/` as `test-only` entries, outside `rules/`, so
no pack can reference them. `tools/build_packs.py` stages them under
`build/fixtures/<kind>/<os|common>/` (outside `dist/`) and the runner copies the
current OS's into its throwaway pack copy. Sigma fixtures match only a unique
command-line marker, so they cannot compete with a production detection on the
same event. `--no-fixtures` runs production content alone.

### Reading a run

`report-<platform>.json` and the job summary keep three outcomes apart:
**required misses** (fail the run), **allowed failures** (manifest
`allow_failure`, with a mandatory `allow_failure_reason`) and **skips**
(manifest `skip`, a reason string; the test is not run). A failed test records
the expected alert, the trigger's exit code and output, and the rule names the
engine did alert on while waiting (`alerts_seen`); CI uploads the engine logs
and `engine.stdout.log` beside the report.

---

## Layout

```text
tests/atomic/
├── run_atomics.py          orchestrator (pure stdlib: runs under `sudo python3`)
├── manifest.json           rule id  ->  atomic script + how to match the alert
├── test_run_atomics.py     unit tests: alert matching, canary blob/hash agreement
├── canary/make_canary.py   generates the deterministic hash-IOC canary binaries
└── atomics/
    ├── linux/*.sh          one atomic action per Linux rule
    ├── windows/*.ps1       one atomic action per Windows rule
    └── macos/*.sh          one atomic action per macOS rule
```

CI: [`.github/workflows/atomic.yml`](../../.github/workflows/atomic.yml).

---

## What the runner does

1. Picks the most inclusive pack for the OS from `dist/index.json` (packs are
   cumulative - `linux-advanced`, `windows-hunting`), copies it next to the
   engine, and overlays the test-only IOC fixtures from `build/fixtures/` onto
   that copy (`--no-fixtures` to skip).
2. Writes a `config.toml` pointing the engine's Sigma/YARA/IOC paths at that
   pack and alerts at `<engine-dir>/logs/`.
3. Starts `rustinel run` (**privileged**: Linux eBPF needs root, Windows ETW
   needs admin, macOS EndpointSecurity needs root).
4. For each test: snapshots the alert log, runs the atomic action, polls for a
   matching alert (default 30s).
5. Stops the engine, writes `report-<platform>.json` and a GitHub step summary.
   Both include the actual `engine_version`, which is also printed in job output.
   Reports retain expected alert details, action exit codes and failed action
   output. Startup failures include `engine_error`; CI uploads the report, engine
   logs and `engine.stdout.log` even after a failure.
   Exit code is non-zero if any gating test failed to fire (2 if the engine
   never started).

---

## Run it locally

From the repo root. First build the packs, install the pinned release, then run
privileged. Linux and macOS use the same installer:

```bash
uv sync --frozen
uv run python tools/build_packs.py
curl -fsSL https://raw.githubusercontent.com/Karib0u/rustinel/v1.9.1/scripts/install/install.sh \
  | sh -s -- --dir tests/atomic/.engine --version 1.9.1

# Linux:
sudo python3 tests/atomic/run_atomics.py --platform linux

# macOS:
sudo python3 tests/atomic/run_atomics.py --platform macos
```

On a local macOS machine, grant Full Disk Access to the installed `Rustinel.app`
if Endpoint Security reports `NotPermitted`; see the installer output. The
released binary carries the EndpointSecurity entitlement and runs as root.

Windows, from an elevated PowerShell:

```powershell
uv sync --frozen
uv run python tools\build_packs.py
Invoke-WebRequest https://raw.githubusercontent.com/Karib0u/rustinel/v1.9.1/scripts/install/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1 `
  -InstallDir tests\atomic\.engine -Version 1.9.1
python tests\atomic\run_atomics.py --platform windows
```

To test a local engine build, pass `--engine-bin` (use `rustinel.exe` on Windows).
On macOS the source build must carry the EndpointSecurity entitlement:

```bash
sudo python3 tests/atomic/run_atomics.py --platform linux \
  --engine-bin ../rustinel/target/release/rustinel
```

No-engine commands (work anywhere):

```bash
python3 tests/atomic/run_atomics.py --list                  # selected tests + join keys
python3 tests/atomic/run_atomics.py --check-coverage        # manifest vs artifact test_status
python3 tests/atomic/run_atomics.py --check-coverage --strict-essential
```

For a focused firing run, add `--filter canary --platform linux` to the privileged
harness command. Filtered runs do not replace the full suite for a pin update.

---

## Adding a test

1. Write a safe atomic action under `atomics/linux/`, `atomics/windows/` or
   `atomics/macos/` that produces the telemetry the rule keys on (read the
   rule's `detection:` block). Make it clean up after itself. (macOS ships no
   GNU `timeout`: background the process and `kill` it, or bound the tool
   itself - e.g. `curl --max-time`.)
2. Add an entry to `manifest.json` with the rule `id`, `name`, `platform`,
   `engine`, `script`. For Sigma/YARA the title resolves automatically; for IOC
   or anything else, add `expect: {field, contains}`.
   `expect` also accepts a list of conditions that must all match the same alert.
   Each condition uses `field` and one of `equals`, `contains`, or `endswith`.
   The Run key atomic requires both the rule name and a registry path ending in
   `\CurrentVersion\Run\RustinelAtomicTest`, so background registry activity
   cannot satisfy it.
   Add `negatives: [{script, marker}]` for benign activity that must **not** raise the
   rule (for example a registry value written back to its default). After the
   positive fires, the runner runs each negative script once, waits
   `--negative-wait` seconds (default 8) and fails if the rule alerts on an event
   whose alert JSON contains `marker` (a string or list of strings). The marker
   ties the alert to the negative action, so a late duplicate of the positive
   cannot fail it. Several manifest entries may share one rule `id` to cover
   separate detection branches.
3. `python3 tests/atomic/run_atomics.py --list` to confirm the join key resolves.
4. Flip that artifact's `test_status` to `atomic`.
   `--check-coverage` reports platform-specific manifest gaps and Essential
   rules still marked `none`. Add `--strict-essential` when you want those
   Essential gaps, or manual entries without `test_reason`, to fail the check.

Use `"allow_failure": true` for environment-dependent tests, and for a test
whose point is to *settle* an open question (the WMI subscription rule, the
canary executables on their first CI run) - they are reported but do not gate CI.

## Test-only fixtures

Some tests need content that must never reach a production pack. Those artifacts
live under `preview/` with a `test-only` entry in `preview/preview.yml`;
`tools/build_packs.py` flattens the IOC ones into `build/fixtures/ioc/` (outside
`dist/`), and the runner overlays that directory onto its throwaway copy of the
pack under test. Pass `--no-fixtures` to run against production content alone, or
`--fixtures-dir` to point somewhere else.
