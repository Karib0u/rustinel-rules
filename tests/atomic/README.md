# Atomic firing tests

Real-condition firing tests for the detection content in this repo.

`tools/validate.py` proves a rule is *well-formed*. These tests prove it
*actually fires*: they install the [rustinel](https://github.com/Karib0u/rustinel)
engine on real **Windows** and **Linux** runners, perform a small safe *atomic
action* for each rule (the behaviour the rule is meant to catch), and verify the
engine raised an alert.

```text
atomic action  ->  real OS telemetry (eBPF / ETW)  ->  rustinel  ->  alert?
   (a script)        (process / file / registry)       (engine)     (we check)
```

> **Status:** ready to run once the engine publishes releases + install scripts.
> The workflow installs released binaries; until those exist, run locally against
> a source build with `--engine-bin` (see below).

---

## How a test is judged

The engine writes alerts as ECS NDJSON to `logs/alerts.json.<date>`. A test
**passes** when a new alert appears whose join key matches the rule:

| Engine | Join key the runner checks |
| --- | --- |
| Sigma / YARA | `rule.name` equals the rule's **title** (resolved by `id` from `rules/`) |
| IOC / custom | an explicit `expect: {field, contains}` (IOC alerts use `rule.name = "ioc:<kind>:<indicator>"`, so EICAR matches on `rule.description ~ "EICAR"`) |

Most rules are *behavioural* (they match a process command line, a file path, a
registry key), so the atomic actions are **safe simulations** — a reverse-shell
command line aimed at a closed local port, `powershell -EncodedCommand` running a
benign `Write-Host`, a cron file containing `true`, an HKCU Run value pointing at
notepad. Nothing malicious executes; the telemetry is what trips the rule. EICAR
is the one real test artifact, for the IOC/file-hash path.

---

## Layout

```text
tests/atomic/
├── run_atomics.py          orchestrator (pure stdlib: runs under `sudo python3`)
├── manifest.json           rule id  ->  atomic script + how to match the alert
└── atomics/
    ├── linux/*.sh          one atomic action per Linux rule
    └── windows/*.ps1       one atomic action per Windows rule
```

CI: [`.github/workflows/atomic.yml`](../../.github/workflows/atomic.yml).

---

## What the runner does

1. Picks the most inclusive pack for the OS from `dist/index.json` (packs are
   cumulative — `linux-advanced`, `windows-hunting`) and copies it next to the
   engine.
2. Writes a `config.toml` pointing the engine's Sigma/YARA/IOC paths at that
   pack and alerts at `<engine-dir>/logs/`.
3. Starts `rustinel run` (**privileged**: Linux eBPF needs root, Windows ETW
   needs admin).
4. For each test: snapshots the alert log, runs the atomic action, polls for a
   matching alert (default 20s).
5. Stops the engine, writes `report-<platform>.json` and a GitHub step summary.
   Exit code is non-zero if any gating test failed to fire (2 if the engine
   never started).

---

## Run it locally

From the repo root. First build the packs, then run privileged.

```bash
uv run python tools/build_packs.py            # produces dist/

# Engine via release (once published):
#   curl -fsSL .../install.sh | sh -s -- --dir tests/atomic/.engine
#   sudo python3 tests/atomic/run_atomics.py --platform linux
#
# Engine from a local source build of the sibling rustinel repo:
sudo python3 tests/atomic/run_atomics.py --platform linux \
  --engine-bin ../rustinel/target/release/rustinel
```

Windows, from an elevated PowerShell:

```powershell
uv run python tools\build_packs.py
python tests\atomic\run_atomics.py --platform windows `
  --engine-bin ..\rustinel\target\release\rustinel.exe
```

No-engine commands (work anywhere, including macOS):

```bash
python3 tests/atomic/run_atomics.py --list                  # selected tests + join keys
python3 tests/atomic/run_atomics.py --check-coverage        # manifest vs rules' test_status
python3 tests/atomic/run_atomics.py --filter eicar --platform linux
```

---

## Adding a test

1. Write a safe atomic action under `atomics/linux/` or `atomics/windows/` that
   produces the telemetry the rule keys on (read the rule's `detection:` block).
   Make it clean up after itself.
2. Add an entry to `manifest.json` with the rule `id`, `name`, `platform`,
   `engine`, `script`. For Sigma/YARA the title resolves automatically; for IOC
   or anything else, add `expect: {field, contains}`.
3. `python3 tests/atomic/run_atomics.py --list` to confirm the join key resolves.
4. (Optional) Flip that rule's `rustinel.test_status` to `atomic`.
   `--check-coverage` reports which `atomic`-marked rules still lack a test.

Use `"allow_failure": true` for environment-dependent tests (e.g. EICAR) so they
are reported but do not gate CI.
