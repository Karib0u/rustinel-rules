# Packs & rule inventory

The catalog of detection packs and every artifact each one contributes. Packs are **cumulative**:
a higher level `extends` the one below it, so the tables below list only what each level **adds** —
the resolved pack also includes everything from the levels it extends.

```text
Essential  ⊂  Advanced  ⊂  Hunting
```

| Pack | Level | Default | Expected FP | Status |
| ---- | ----- | :-----: | ----------- | ------ |
| [Windows Essential](#windows-essential) | essential | ✅ | low | experimental |
| [Windows Advanced](#windows-advanced) | advanced | ❌ | medium | experimental |
| [Windows Hunting](#windows-hunting) | hunting | ❌ | high | experimental |
| [Linux Essential](#linux-essential) | essential | ✅ | low | experimental |
| [Linux Advanced](#linux-advanced) | advanced | ❌ | medium | experimental |
| [macOS Essential](#macos-essential) | essential | ❌ | low | experimental |
| [macOS Advanced](#macos-advanced) | advanced | ❌ | medium | experimental |

> All packs declare `pack_schema_version: 1`, `requires_rustinel: ">=1.0.2"`, and license
> `DRL-1.1`. `status: experimental` reflects the early state of v1 content — expect curation to
> tighten as coverage grows.

---

## Windows

### Windows Essential

Low-noise, high-confidence Windows detections. **Safe default** (`default: true`). The pack also
ships the **EICAR** IOC set for end-to-end pipeline testing.

*Telemetry:* `process_creation`, `registry_event`, `task_creation`, `file_scan`

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
| Scheduled Task Created With Suspicious Action | Sigma | task_creation | T1053.005, T1059, T1105 |
| Mimikatz credential-dumping strings | YARA | file_scan | T1003.001 |
| EICAR safe end-to-end IOC test set | IOC | file_scan | — |

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

Low-noise, high-confidence Linux detections. **Safe default** (`default: true`). Ships the **EICAR**
IOC set for end-to-end testing.

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
| EICAR safe end-to-end IOC test set | IOC | file_scan | — |

### Linux Advanced

Linux Essential **plus** broader detections (notably persistence and execution). More false
positives may occur — especially from package installs — so tune before relying on by default.

*Adds telemetry:* none

| Rule (added on top of Essential) | Type | Category | ATT&CK |
| -------------------------------- | ---- | -------- | ------ |
| Systemd Unit Persistence | Sigma | file_event | T1543.002 |
| Cron Job Persistence | Sigma | file_event | T1053.003 |
| Shell Profile / RC File Persistence | Sigma | file_event | T1546.004 |
| Execution from World-Writable / Temporary Directory | Sigma | process_creation | T1059.004, T1036 |
| Linux Download and Execute Piped to Shell | Sigma | process_creation | T1059.004, T1105 |

---

## macOS

> macOS packs are **experimental and post-v1** — not yet production-ready — so both are
> `default: false`. Content is built on Apple's EndpointSecurity sensor (process, file, network,
> DNS). The process exec event carries full `CommandLine` (argv) natively, but **code-signing
> fields are not yet exposed**, which caps how low the false-positive rate can go. Exposing
> code-signing telemetry is a planned engine enhancement that would let several Advanced rules
> graduate to Essential.

### macOS Essential

Low-noise, high-confidence macOS detections aimed at the dominant macOS threats (infostealers,
keychain theft, Gatekeeper bypass, cryptominers). Ships the **EICAR** IOC set for end-to-end
pipeline testing.

*Telemetry:* `process_creation`, `file_scan`

| Rule | Type | Category | ATT&CK |
| ---- | ---- | -------- | ------ |
| Keychain Credential Dump via security | Sigma | process_creation | T1555.001 |
| osascript Credential Prompt or Suspicious Admin Shell | Sigma | process_creation | T1059.002, T1056.002 |
| Gatekeeper or Quarantine Protection Disabled | Sigma | process_creation | T1553.001, T1562.001 |
| macOS Reverse Shell via /dev/tcp | Sigma | process_creation | T1059.004, T1105 |
| Cryptominer Mach-O strings | YARA | file_scan | T1496 |
| EICAR safe end-to-end IOC test set | IOC | file_scan | — |

### macOS Advanced

macOS Essential **plus** broader detections. More false positives may occur — notably from
application installers — so tune per environment before relying on by default.

*Adds telemetry:* `file_event`

| Rule (added on top of Essential) | Type | Category | ATT&CK |
| -------------------------------- | ---- | -------- | ------ |
| Launch Agent or Daemon Persistence Plist Created | Sigma | file_event | T1543.001, T1543.004 |
| Shell Download-and-Execute Pipe Cradle | Sigma | process_creation | T1105, T1059.004 |
| Local Admin Account Created via Directory Services | Sigma | process_creation | T1136.001, T1098 |
| Execution from World-Writable / Temporary Directory | Sigma | process_creation | T1059.004, T1036 |

---

## Shared content

### EICAR test IOC set (`ioc-eicar-test`)

A safe, standardized [EICAR](https://www.eicar.org/download-anti-malware-testfile/) anti-malware
test file, included in each Essential pack (`os: common`). Its hashes (MD5/SHA1/SHA256) let you
confirm the IOC pipeline is wired end to end: build a pack, point Rustinel's `[ioc]` config at it,
drop an EICAR file on disk, and you should see a hash match. Replace/extend with real curated
indicators over time.

---

## Reading this in `index.json`

After a build, `dist/index.json` carries the resolved, machine-readable version of everything above:
per-pack `rule_count`, `ioc_count`, `attack_coverage`, `telemetry_requirements`, the list of
resolved `rules`, a `sha256`, and the drop-in `engine` paths. See
[the build output](repository.md#indexjson-shape).
