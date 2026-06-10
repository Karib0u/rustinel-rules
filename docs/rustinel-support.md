# Rustinel support reference

The authoritative list of what the Rustinel engine can detect: which telemetry it collects, the
Sigma log sources and fields it understands, the Sigma operators/modifiers it implements, how YARA
is applied, and the IOC types and file formats it loads.

> **Author against this page.** A rule whose log source, fields or modifiers fall outside what's
> listed here will be skipped at load time or simply never match. `tools/validate.py` enforces the
> telemetry side of this; the rest is up to you.

This reference tracks the engine source: telemetry categories from `src/engine/logsource.rs`, field
maps from `src/models/fields.rs`, Sigma operators from `src/engine/matcher.rs`, and IOC behavior from
`src/ioc/`.

> **Canonical source.** The engine's own
> [Detection reference](https://github.com/Karib0u/rustinel/blob/main/docs/detection.md) is the
> authoritative, source-derived description of these capabilities. This page restates the
> author-relevant subset and layers on the `rustinel-rules` conventions (the exact telemetry channel
> names `validate.py` accepts, the new-rule checklist). If the two ever disagree, the engine doc wins
> — open an issue so we can re-sync this page.

---

## 1. Platforms & sensors

| Platform | Sensor | Telemetry collected |
| -------- | ------ | ------------------- |
| Windows 10/11, Server 2016+ | ETW | process, image load, network, file, registry, DNS, PowerShell, WMI, service, task |
| Linux 5.8+ (with BTF) | eBPF | process, network, file, DNS |
| macOS 11+ | Endpoint Security + `/dev/bpf` | process, file, network, DNS |

Windows coverage is the broadest. Linux and macOS currently focus on process, network, file and
DNS. On all platforms, **YARA and file-hash IOC scanning run on process creation** (the `file_scan`
channel).

---

## 2. Supported telemetry / Sigma log source categories

Rustinel routes events by Sigma **log source**. A rule loads only if its `logsource` maps to a
category the engine collects on the current platform. Supported categories:

| Sigma category | Windows | Linux | macOS | Notes |
| -------------- | :-----: | :---: | :---: | ----- |
| `process_creation` | ✅ | ✅ | ✅ | |
| `network_connection` | ✅ | ✅ | ✅ | macOS network is best-effort process-attributed |
| `file_event` | ✅ | ✅ | ✅ | generic file activity |
| `file_create` / `file_delete` / `file_change` / `file_rename` | ✅ | ✅ | ✅ | file sub-categories |
| `dns_query` (`dns`) | ✅ | ✅ | ✅ | Linux/macOS: outbound plaintext queries (`QueryName` + `RecordType`); macOS DNS is not process-attributed |
| `registry_event` / `registry_add` / `registry_set` / `registry_delete` | ✅ | — | — | Windows only |
| `image_load` | ✅ | — | — | Windows only |
| `ps_script` | ✅ | — | — | PowerShell ScriptBlock logging |
| `wmi_event` | ✅ | — | — | Windows only |
| `service_creation` | ✅ | — | — | Windows Event ID 7045 |
| `task_creation` | ✅ | — | — | Windows Event ID 106 |

Plus one **scan** channel used by YARA / hash IOC:

| Channel | Meaning |
| ------- | ------- |
| `file_scan` | Executable scanned on process creation (YARA disk scan + IOC file hashing). Declare this in `rustinel.telemetry` / `telemetry_requirements` for YARA and hash-IOC content. |

These category names are exactly the values accepted in a rule's `rustinel.telemetry` list and a
pack's `telemetry_requirements`. `validate.py` rejects anything else.

### Log source product & service

- **`product`** must match the platform: `windows`, `linux`, or `macos`. A rule with a mismatched
  product is skipped as a product mismatch (e.g. a `product: linux` rule on a Windows host).
- **`service`** is optional. Recognized Windows services: `sysmon`, `security`, `system`,
  `taskscheduler` / `task scheduler`, `powershell` / `powershell-classic` /
  `microsoft-windows-powershell`, `dns-client` / `dns`, `wmi`. The engine maps community
  Sysmon-style log sources onto its own telemetry, so most upstream Sigma `logsource` blocks work
  unchanged.

A typical Windows process rule:

```yaml
logsource:
  category: process_creation
  product: windows
```

---

## 3. Supported Sigma fields (per category)

These are the normalized field names available in `detection:` selections. Field names are the
standard Sigma/Sysmon names; Rustinel maps them onto native ETW/eBPF/ESF properties internally, so
you write portable Sigma.

### `process_creation`

`Image`, `OriginalFileName`, `Product`, `Description`, `TargetImage`, `CommandLine`, `ProcessId`,
`ProcessStartTime`, `ParentProcessId`, `ParentImage`, `ParentCommandLine`, `CurrentDirectory`,
`IntegrityLevel`, `User`, `LogonId`, `LogonGuid`

> **Linux: command-line and parent fields are best-effort.** The kernel exec event itself carries
> only `Image`, `ProcessId` and `User` (uid). `CommandLine`, `ParentProcessId`, `ParentImage`,
> `ParentCommandLine` and `CurrentDirectory` are enriched from `/proc/<pid>` when the event is
> processed, so they are populated for normally-lived processes but may be **absent for a very
> short-lived process** that exits before the read completes (and `CommandLine` reflects the
> process's current `/proc/<pid>/cmdline`, which a process can overwrite). Write Linux
> `process_creation` rules so they still match meaningfully on `Image` alone, and treat
> `CommandLine`/parent fields as additional signal rather than a guaranteed precondition.
> `IntegrityLevel`, `LogonId` and `LogonGuid` are Windows-only.
>
> **macOS: command-line and parent fields are native, except `ParentCommandLine`.** ESF exec events
> carry `CommandLine` (argv), `ParentImage`, `ParentProcessId` and `CurrentDirectory` directly, so
> they are reliably populated (no `/proc` race). However **`ParentCommandLine` is not provided** on
> macOS — don't depend on it in macOS rules. Code-signing fields are not exposed yet either, a
> known gap planned for a future engine enhancement.

### `file_event` (and `file_create` / `file_delete` / `file_change` / `file_rename`)

`SourceFilename`, `TargetFilename`, `ProcessId`, `Image`, `CreationUtcTime`,
`PreviousCreationUtcTime`, `User`

### `registry_event` (and `registry_add` / `registry_set` / `registry_delete`) — Windows

`TargetObject`, `Details`, `ProcessId`, `Image`, `EventType`, `User`, `NewName`

### `network_connection`

`DestinationIp`, `SourceIp`, `DestinationPort`, `SourcePort`, `ProcessId`, `Image`, `User`,
`DestinationHostname`, `Protocol`

> On macOS, network telemetry comes from `/dev/bpf` packet capture: `DestinationHostname` is not
> populated, and `ProcessId`/`Image` are best-effort (matched against open sockets by port, so a
> short-lived connection may be unattributed).

### `dns_query`

`QueryName`, `QueryResults`, `RecordType`, `QueryStatus`, `ProcessId`, `Image`

> On Linux and macOS, `QueryName` and `RecordType` are populated for outbound plaintext queries;
> `QueryResults` and `QueryStatus` are not parsed yet. On macOS, DNS is captured at the packet layer
> and is **not** attributed to a process, so `Image` and `ProcessId` are empty on macOS DNS events.

### `image_load` — Windows

`ImageLoaded`, `ProcessId`, `Image`, `OriginalFileName`, `Product`, `Description`, `Signed`,
`Signature`, `User`

### `ps_script` — Windows

`ScriptBlockText`, `ScriptBlockId`, `Path`, `ProcessId`, `Image`, `User`

### `wmi_event` — Windows

`Operation`, `User`, `Query`, `ProcessId`, `Image`, `EventNamespace`, `EventType`,
`DestinationHostname`

### `service_creation` — Windows

`ServiceName`, `ServiceFileName`, `ServiceType`, `StartType`, `AccountName`, `User`, `ProcessId`,
`Image`

### `task_creation` — Windows

`TaskName`, `TaskContent`, `UserName`, `User`, `ProcessId`, `Image`

> **Unmapped fields never match.** If a selection references a field not in the relevant list above,
> that field is treated as missing on every event, so the rule won't fire. Stick to these names.

---

## 4. Supported Sigma detection logic

### Conditions

The condition expression supports:

- Boolean operators: `and`, `or`, `not` (and uppercase `AND` / `OR` / `NOT`), with parentheses.
- `1 of them` / `all of them`.
- Wildcard aggregation: `1 of selection*` / `all of filter*` (matches selection names by prefix).

### Selections

- Multiple fields in one selection are combined with **AND**.
- A list of values for one field is combined with **OR** (unless the `|all` modifier is used, which
  requires **all** values to match).
- A bare list of strings (keyword selection) matches if any value appears in **any** field of the
  event.

### Value matching

| Form | Behavior |
| ---- | -------- |
| Plain string | Exact match, **case-insensitive** by default. |
| `*` / `?` wildcards | Glob → regex (`*` = any, `?` = one char). Escaped `\*`, `\?`, `\\` are literal. |
| Empty string `''` | Field-exists check. |
| `null` | Field-missing check. |
| Number | Exact match on string form (or numeric compare with a comparison modifier). |

### Field modifiers (`Field|modifier`)

All of these are implemented and pass validation:

| Modifier | Effect |
| -------- | ------ |
| `contains` | Substring match. |
| `startswith` / `endswith` | Prefix / suffix match. |
| `all` | Every listed value must match (AND across the value list). |
| `cased` | Case-**sensitive** matching. |
| `re` | Treat the value as a regular expression. |
| `i` / `m` / `s` | Regex flags (case-insensitive / multiline / dotall) — used with `re`. |
| `windash` | Normalize command-line dashes/slashes (`-`, `/`, en/em dash) when matching. |
| `fieldref` | Compare this field against the value of **another field** in the same event. |
| `exists` | Boolean field-presence check (`true` / `false`). |
| `cidr` | Match an IP field against a CIDR network. |
| `base64` | Match the base64 encoding of the value. |
| `base64offset` | Match base64 with the three offset permutations. |
| `wide` / `utf16` / `utf16le` | Match the UTF-16LE (wide) encoding of the value. |
| `utf16be` | Match the UTF-16BE encoding of the value. |
| `lt` / `le` (`lte`) / `gt` / `ge` (`gte`) | Numeric comparison. |

> An **unsupported modifier** is a hard error at compile time — the rule fails to load. Keep to the
> table above.

---

## 5. YARA support

- **Disk scan on process creation.** When a process starts, Rustinel scans the executable image
  against the loaded YARA rules. This is a high-signal scanning point, not full on-access AV.
- **Optional memory scanning.** Rustinel can scan private executable memory regions to catch packed,
  obfuscated, or runtime-unpacked payloads (off by default; see `scanner.yara_memory_*` in the
  [config reference](usage.md#yara-scanner)).
- **Allowlisting.** OS-shipped directories are allowlisted by default so YARA/IOC/response don't act
  on trusted system binaries.

YARA rules are standard `.yar` files. The build and validation read two `meta` fields:

| `meta` field | Use |
| ------------ | --- |
| `id` | Stable artifact id (falls back to the rule name if absent). |
| `attack` | ATT&CK technique id, used for pack `attack_coverage` drift checks. |

YARA content should declare `telemetry = "file_scan"` (in `meta`) and be referenced from a pack like
any other artifact.

---

## 6. IOC support

IOC matching is fast, deterministic lookup. Rustinel loads four flat files (the build generates them
from your typed IOC sets):

| Type | File | What it matches | Format details |
| ---- | ---- | --------------- | -------------- |
| **Hashes** | `hashes.txt` | File hash on process-start scan | MD5 (32), SHA1 (40), SHA256 (64) hex; case-insensitive. |
| **IPs** | `ips.txt` | Network connection IPs | Single IP **or** CIDR range. |
| **Domains** | `domains.txt` | DNS `QueryName` (Win/Linux/macOS) and hostnames | Exact, or prefix with `.` / `*.` to match subdomains. |
| **Path regex** | `paths_regex.txt` | Process / file paths | Regular expression, matched **case-insensitively**. |

### Flat-file format

The engine reads one indicator per line as `VALUE;COMMENT`:

```text
# Lines starting with # or // are comments and are ignored.
44d88612fea8a8f36de82e1278abb02f;[ioc-eicar-test] EICAR test file (MD5)
198.51.100.7;suspicious C2
198.51.100.0/24
*.evil.example;phishing infra
```

You don't write these files by hand — author **typed IOC sets** under `rules/ioc/` (see
[authoring](authoring.md#ioc-sets) and the [IOC schema](../schemas/ioc.schema.json)); the build
flattens them and tags each line with its source set id for provenance.

---

## 7. Alert output

Rustinel writes alerts as **ECS 9.4.0 NDJSON** to `logs/alerts.json.<date>`, which ingests cleanly
into SIEM/log pipelines. Each Sigma/YARA/IOC match becomes one alert record carrying the rule/IOC
identity, the matched event fields, and ATT&CK context where available.

## 8. Optional active response

Rustinel can optionally terminate a matching process. It ships with **dry-run** and **allowlist**
safeguards and a minimum-severity gate, all off/conservative by default. See
[config reference → response](usage.md#active-response).

---

## Quick compatibility checklist for a new rule

- [ ] Log source `category` is in the [supported categories](#2-supported-telemetry--sigma-log-source-categories) table.
- [ ] Log source `product` matches the target platform.
- [ ] Every field referenced is in that category's [field list](#3-supported-sigma-fields-per-category).
- [ ] Every `|modifier` used is in the [modifier table](#field-modifiers-fieldmodifier).
- [ ] `rustinel.telemetry` lists the right channel(s) (`file_scan` for YARA/hash IOC).
- [ ] `uv run python tools/validate.py` passes.
