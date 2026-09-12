# Packs & rule inventory

The catalog of detection packs and every artifact each one contributes. Packs are **cumulative**:
a higher level `extends` the one below it, so the tables below list only what each level **adds** —
the resolved pack also includes everything from the levels it extends.

```text
Essential  ⊂  Advanced  ⊂  Hunting
```

| Pack | Level | Default | Expected FP | Status | Min engine |
| ---- | ----- | :-----: | ----------- | ------ | ---------- |
| [Windows Essential](#windows-essential) | essential | ✅ | low | experimental | `>=1.4.0` |
| [Windows Advanced](#windows-advanced) | advanced | ❌ | medium | experimental | `>=1.4.1` |
| [Windows Hunting](#windows-hunting) | hunting | ❌ | high | experimental | `>=1.4.1` |
| [Linux Essential](#linux-essential) | essential | ✅ | low | experimental | `>=1.0.2` |
| [Linux Advanced](#linux-advanced) | advanced | ❌ | medium | experimental | `>=1.0.2` |
| [macOS Essential](#macos-essential) | essential | ❌ | low | experimental | `>=1.0.2` |
| [macOS Advanced](#macos-advanced) | advanced | ❌ | medium | experimental | `>=1.0.2` |

> All packs declare `pack_schema_version: 2`, `requires_rustinel: ">=1.0.2"`, and license
> `DRL-1.1`. `status: experimental` reflects the early state of v1 content — expect curation to
> tighten as coverage grows.

---

## Windows

### Windows Essential

Low-noise, high-confidence Windows detections. **Safe default** (`default: true`).

*Telemetry:* `process_creation`, `registry_event`, `wmi_event`, `file_scan`

| Rule | Type | Category | ATT&CK |
| ---- | ---- | -------- | ------ |
| Suspicious Encoded PowerShell Command Line | Sigma | process_creation | T1059.001, T1027 |
| LSASS Memory Dump via comsvcs.dll MiniDump | Sigma | process_creation | T1003.001 |
| Volume Shadow Copy Deletion | Sigma | process_creation | T1490 |
| Regsvr32 Remote Scriptlet Execution / Squiblydoo | Sigma | process_creation | T1218.010 |
| Mshta Remote or Inline Script Execution | Sigma | process_creation | T1218.005 |
| Office Application Spawning a Command Shell | Sigma | process_creation | T1566.001, T1059 |
| Windows Event Log Cleared via Command Line | Sigma | process_creation | T1070.001 |
| Microsoft Defender Tampering via Registry | Sigma | registry_event | T1562.001 |
| Registry Hive Dump via reg.exe save | Sigma | process_creation | T1003.002 |
| UAC Bypass via Auto-Elevating LOLBin | Sigma | process_creation | T1548.002 |
| Active Directory Database (NTDS.dit) Extraction | Sigma | process_creation | T1003.003 |
| WDigest Cleartext Credential Caching Enabled | Sigma | registry_event | T1003.001 |
| Mimikatz credential-dumping strings | YARA | file_scan | T1003.001 |

### Windows Advanced

Windows Essential **plus** broader production detections. More false positives may occur than in
Essential; tune per environment before relying on by default.

*Adds telemetry:* `ps_script`, `service_creation`

| Rule (added on top of Essential) | Type | Category | ATT&CK |
| -------------------------------- | ---- | -------- | ------ |
| Rundll32 Execution Without Standard Arguments | Sigma | process_creation | T1218.011 |
| Local Account Created or Added to Administrators | Sigma | process_creation | T1136.001, T1098 |
| Registry Run Key Persistence | Sigma | registry_event | T1547.001 |
| PowerShell Download-and-Execute Cradle | Sigma | ps_script | T1105, T1059.001 |
| Suspicious Service Binary Path | Sigma | service_creation | T1543.003 |
| Scheduled Task Creation via Schtasks | Sigma | process_creation | T1053.005 |
| WMI Process Execution via WMIC | Sigma | process_creation | T1047 |

### Windows Hunting

Windows Advanced **plus** broad, noisier hunting content for analyst-driven investigation. Not
enabled by default and not suitable as a standing alert source without tuning.

| Rule (added on top of Advanced) | Type | Category | ATT&CK |
| ------------------------------- | ---- | -------- | ------ |
| Certutil Used to Download Remote Content (Hunting) | Sigma | process_creation | T1105 |

---

## Linux

> There is no Linux Hunting pack yet. Linux content focuses on file- and process-based persistence
> and execution, matching the engine's eBPF coverage (process, network, file, DNS).

### Linux Essential

Low-noise, high-confidence Linux detections. **Safe default** (`default: true`).

*Telemetry:* `process_creation`, `file_event`, `file_scan`

| Rule | Type | Category | ATT&CK |
| ---- | ---- | -------- | ------ |
| Dynamic Linker Hijacking via ld.so.preload | Sigma | file_event | T1574.006 |
| SSH authorized_keys Created or Replaced | Sigma | file_event | T1098.004 |
| Sudoers Configuration Tampering | Sigma | file_event | T1548.003 |
| Linux Reverse Shell via /dev/tcp | Sigma | process_creation | T1059.004, T1105 |
| Linux Web Server Spawning Interactive Shell | Sigma | process_creation | T1059.004, T1505.003 |
| SSH Daemon Configuration Tampering | Sigma | file_event | T1098.004, T1562.001 |
| XMRig / coinminer strings in Linux ELF binaries | YARA | file_scan | T1496 |

### Linux Advanced

Linux Essential **plus** broader detections (notably persistence and execution). More false
positives may occur — especially from package installs — so tune before relying on by default.

*Adds telemetry:* `file_delete`, `file_rename`

| Rule (added on top of Essential) | Type | Category | ATT&CK |
| -------------------------------- | ---- | -------- | ------ |
| Systemd Unit Persistence | Sigma | file_event | T1543.002 |
| Cron Job Persistence | Sigma | file_event | T1053.003 |
| Shell Profile / RC File Persistence | Sigma | file_event | T1546.004 |
| Execution from World-Writable / Temporary Directory | Sigma | process_creation | T1059.004, T1036 |
| Linux Download and Execute Piped to Shell | Sigma | process_creation | T1059.004, T1105 |
| Shell History File Deleted | Sigma | file_delete | T1070.003 |
| Shell History File Renamed Away | Sigma | file_rename | T1070.003 |
| Shell History Destroyed in Place | Sigma | process_creation | T1070.003 |

---

## macOS

> macOS packs are **experimental and post-v1** — not yet production-ready — so both are
> `default: false`. Content is built on Apple's EndpointSecurity sensor (process, file, network,
> DNS). The process exec event carries full `CommandLine` (argv) natively, and engine v1.6.0 added
> the code-signing fields (`Signed`, `TeamId`, `IsPlatformBinary`, …) that cap how low the
> false-positive rate can go; no current rule uses them yet, which is the main headroom for letting
> Advanced rules graduate to Essential.
>
> The macOS atomic leg **gates CI** as of this release. Endpoint Security was expected to need an
> entitled runner; it initialises under `sudo` on hosted `macos-latest`, and every macOS rule now
> has a passing atomic test.

### macOS Essential

Low-noise, high-confidence macOS detections aimed at the dominant macOS threats (infostealers,
keychain theft, Gatekeeper bypass, cryptominers).

*Telemetry:* `process_creation`, `file_scan`

| Rule | Type | Category | ATT&CK |
| ---- | ---- | -------- | ------ |
| Keychain Credential Dump via security | Sigma | process_creation | T1555.001 |
| osascript Credential Prompt or Suspicious Admin Shell | Sigma | process_creation | T1059.002, T1056.002 |
| Gatekeeper or Quarantine Protection Disabled | Sigma | process_creation | T1553.001, T1562.001 |
| macOS Reverse Shell via /dev/tcp | Sigma | process_creation | T1059.004, T1105 |
| Browser Credential Store Targeted on a Command Line | Sigma | process_creation | T1555.003 |
| Cryptominer Mach-O strings | YARA | file_scan | T1496 |

### macOS Advanced

macOS Essential **plus** broader detections. More false positives may occur — notably from
application installers — so tune per environment before relying on by default.

*Adds telemetry:* `file_event`, `file_delete`, `file_rename`

| Rule (added on top of Essential) | Type | Category | ATT&CK |
| -------------------------------- | ---- | -------- | ------ |
| Launch Agent or Daemon Persistence Plist Created | Sigma | file_event | T1543.001, T1543.004 |
| Shell Download-and-Execute Pipe Cradle | Sigma | process_creation | T1105, T1059.004 |
| Local Admin Account Created via Directory Services | Sigma | process_creation | T1136.001, T1098 |
| Execution from World-Writable / Temporary Directory | Sigma | process_creation | T1059.004, T1036 |
| Shell History File Deleted (macOS) | Sigma | file_delete | T1070.003 |
| Shell History File Renamed Away (macOS) | Sigma | file_rename | T1070.003 |
| Shell History Destroyed in Place (macOS) | Sigma | process_creation | T1070.003 |
| TCC Privacy Database Targeted on a Command Line | Sigma | process_creation | T1005, T1548 |

---

## Shared content

No pack currently ships an IOC set. The packs' `ioc/*.txt` files are still generated (empty) so a
config pointed at them loads cleanly, and curated indicator sets drop straight in when they arrive.

### Why there is no EICAR set any more

Every Essential pack used to ship `ioc-eicar-test`, described as a way to confirm the IOC pipeline
end to end. It could not do that. Rustinel computes hash IOCs from the resolved image path of a
**process start**; a file that is written and read but never executed is never hashed, and EICAR is
a 16-bit DOS `.COM` that cannot become a process image on a supported platform. An operator
following the stated instructions would drop an EICAR file, see nothing, and conclude — wrongly —
that their pipeline was broken.

The set now lives under `preview/` as `test-only` content. See
[usage](usage.md#3-confirm-it-works) for a check that does work, and
[repository](repository.md#non-production-content-preview) for the lifecycle.

## Non-production content

Two detections are parked under `preview/` because the certified engine never populates a field
they require, so they can never match:

| Rule | Was in | Missing field | Blocker |
| ---- | ------ | ------------- | ------- |
| Scheduled Task Created With Suspicious Action | Windows Essential | `task_creation.TaskContent` | [rustinel#479](https://github.com/Karib0u/rustinel/issues/479) |
| Unsigned DLL Loaded from User-Writable Path (Hunting) | Windows Hunting | `image_load.Signed` | [rustinel#320](https://github.com/Karib0u/rustinel/issues/320) |

`tools/validate.py` fails the build if a pack references either one, or any other preview or
test-only artifact.

## Engine requirements

Each pack's `requires_rustinel` is **derived from its own content**, not declared by hand:
`tools/lib.py` maps the capabilities a rule depends on to the release that first provides them, and
`validate.py` fails a pack whose declared floor is lower than what its rules need. Under-claiming is
the dangerous direction — `rustinel doctor` would report the pack as compatible with an engine that
cannot populate the fields its rules select on, so the rules load and silently never match.

Today only Windows content raises the floor: registry value data (`Details`, v1.4.0) and
`service_creation` `ImagePath` (v1.4.1). Linux and macOS content runs on the v1.0.2 baseline.

---

## Reading this in `index.json`

After a build, `dist/index.json` carries the resolved, machine-readable version of everything above:
per-pack `rule_count`, `ioc_count`, `attack_coverage`, `telemetry_requirements`, the list of
resolved `rules`, a `sha256`, and the drop-in `engine` paths. See
[the build output](repository.md#indexjson-shape).
