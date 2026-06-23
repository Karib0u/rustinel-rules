# Using a pack with Rustinel

A materialized pack folder **is** the directory Rustinel loads — there is no glue or conversion
step. Build a pack, unzip it (or point at `dist/<pack>/`), and set the paths in Rustinel's
`config.toml`.

## 1. Build the packs

```bash
uv run python tools/validate.py        # must pass
uv run python tools/build_packs.py     # writes dist/<pack>/, zips, and index.json
```

Each pack appears under `dist/` as both a folder and a versioned zip:

```text
dist/
├── index.json
├── windows-essential/            # <- drop-in folder
│   ├── pack.yml
│   ├── sigma/
│   ├── yara/
│   └── ioc/
└── windows-essential-0.1.0.zip   # <- distributable artifact
```

Pass `--version X.Y.Z` to `build_packs.py` to stamp a release version (default `0.1.0`).

## 2. Point `config.toml` at the pack

Use the paths from the pack's `engine` block in `dist/index.json` (shown here for
`windows-essential`):

```toml
[scanner]
sigma_enabled    = true
sigma_rules_path = "windows-essential/sigma"
yara_enabled     = true
yara_rules_path  = "windows-essential/yara"

[ioc]
enabled          = true
hashes_path      = "windows-essential/ioc/hashes.txt"
ips_path         = "windows-essential/ioc/ips.txt"
domains_path     = "windows-essential/ioc/domains.txt"
paths_regex_path = "windows-essential/ioc/paths_regex.txt"
```

> Swap `windows-essential` for any other pack id (`windows-advanced`, `linux-essential`, …). Because
> packs are cumulative, loading `windows-advanced` already includes everything in
> `windows-essential` — load **one** pack, not several.

Every config key can also be overridden by an environment variable with the `EDR__` prefix and `__`
as the separator, e.g. `EDR__SCANNER__SIGMA_RULES_PATH=...`.

## 3. Confirm it works (EICAR)

The default Essential packs ship the EICAR test IOC set. With the pack loaded, drop a standard EICAR
test file on disk; Rustinel should hash it on access/exec and raise an IOC alert. Alerts are written
as ECS NDJSON to `logs/alerts.json.<date>`.

## 4. Hot reload

Rustinel watches the rule and IOC paths and reloads on change (`reload.enabled = true` by default).
Rebuild a pack into the same location and the engine picks it up without a restart (debounced by
`reload.debounce_ms`).

---

## `config.toml` reference (rule-relevant sections)

Defaults shown are the engine defaults. Only the paths above are required to load a pack; the rest
are tuning knobs.

### `[scanner]` — Sigma & YARA

| Key | Default | Meaning |
| --- | ------- | ------- |
| `sigma_enabled` | `true` | Enable Sigma evaluation. |
| `sigma_rules_path` | `rules/sigma` | Directory of `.yml` Sigma rules (recursive). |
| `yara_enabled` | `true` | Enable YARA scanning. |
| `yara_rules_path` | `rules/yara` | Directory of `.yar` YARA rules (recursive). |
| `yara_allowlist_paths` | (global allowlist) | Path prefixes exempt from YARA scanning. |

<a id="yara-scanner"></a>**YARA memory scanning** (off by default):

| Key | Default | Meaning |
| --- | ------- | ------- |
| `yara_memory_enabled` | `false` | Scan process memory regions, not just the on-disk image. |
| `yara_memory_queue_capacity` | `64` | Max queued processes pending memory scan. |
| `yara_memory_delay_ms` | `750` | Delay after process start before scanning. |
| `yara_memory_max_process_mb` | `64` | Skip processes larger than this. |
| `yara_memory_max_region_mb` | `8` | Skip regions larger than this. |
| `yara_memory_include_private` | `true` | Scan private regions (packed/unpacked payloads). |
| `yara_memory_include_image` | `false` | Include image-backed regions. |
| `yara_memory_include_mapped` | `false` | Include file-mapped regions. |

### `[ioc]` — indicator matching

| Key | Default | Meaning |
| --- | ------- | ------- |
| `enabled` | `true` | Enable IOC matching. |
| `hashes_path` | `rules/ioc/hashes.txt` | File-hash IOCs (MD5/SHA1/SHA256). |
| `ips_path` | `rules/ioc/ips.txt` | IP / CIDR IOCs. |
| `domains_path` | `rules/ioc/domains.txt` | Domain IOCs (`.`/`*.` for subdomains). |
| `paths_regex_path` | `rules/ioc/paths_regex.txt` | Path-regex IOCs (case-insensitive). |
| `default_severity` | `high` | Severity assigned to IOC matches. |
| `max_file_size_mb` | `50` | Max IOC file size loaded. |
| `hash_allowlist_paths` | (global allowlist) | Path prefixes exempt from hash scanning. |

### `[allowlist]` — shared trusted paths

| Key | Default | Meaning |
| --- | ------- | ------- |
| `paths` | OS-shipped dirs (e.g. `C:\Windows\`, `/usr/bin/`, `/System/`) | Trusted prefixes applied to YARA, hash IOC, and response. Per-module allowlists fall back to this. |

### `[response]` — optional active response

| Key | Default | Meaning |
| --- | ------- | ------- |
| `enabled` | `false` | Master switch for active response. |
| `prevention_enabled` | `false` | Actually terminate (vs. dry-run). |
| `min_severity` | `critical` | Minimum alert severity that triggers response. |
| `allowlist_images` / `allowlist_paths` | (global allowlist) | Never act on these. |

### `[reload]` — hot reload

| Key | Default | Meaning |
| --- | ------- | ------- |
| `enabled` | `true` | Watch rule/IOC paths and reload on change. |
| `debounce_ms` | `2000` | Settle time before applying a reload. |

> Config files are searched next to the `rustinel` executable and in the current working directory
> (the latter wins on conflicts). This matters for Windows services, which start in
> `C:\Windows\System32`.

---

## Where packs come from

- **From this repo:** run the two tooling commands above and point at `dist/`.
- **From a release:** download the pack zip + `index.json`, unzip, and use the `engine` paths.

For the engine itself (install, run as a service/daemon, telemetry setup), see the
[Rustinel documentation](https://docs.rustinel.io/).
</content>
