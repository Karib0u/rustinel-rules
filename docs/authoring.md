# Authoring rules

How to add a Sigma rule, YARA rule, or IOC set so it loads, validates, and fires on Rustinel. This
complements [CONTRIBUTING.md](../CONTRIBUTING.md) with engine-facing detail.

> **Prerequisite:** skim the [Rustinel support reference](rustinel-support.md) first. The supported
> log sources, fields and modifiers there are the contract — content outside it won't load or match.

The workflow is the same for every artifact:

1. Add the file under the canonical `rules/` tree with a stable `id`.
2. Reference that `id` from the relevant `pack.yml` `rules:` list.
3. Run `uv run python tools/validate.py`, then `uv run python tools/build_packs.py`.

---

## Sigma rules

Place the rule in `rules/sigma/<os>/` and give it a UUID v4 `id`.

### Required metadata

`validate.py` requires all of these (see [the validator](../tools/validate.py)):

| Field | Notes |
| ----- | ----- |
| `title` | Short, descriptive. |
| `id` | UUID v4, unique across the whole repo. |
| `status` | `experimental` \| `test` \| `stable`. |
| `description` | What it detects and why. |
| `references` | Source / CTI links. |
| `author` | Attribution. |
| `level` | `informational` \| `low` \| `medium` \| `high` \| `critical`. |
| `tags` | Must include at least one `attack.*` tag. |
| `logsource` | Must map to a [supported category](rustinel-support.md#2-supported-telemetry--sigma-log-source-categories). |
| `detection` | Valid Sigma logic using [supported fields](rustinel-support.md#3-supported-sigma-fields-per-category) and [modifiers](rustinel-support.md#field-modifiers-fieldmodifier). |

### Rustinel-specific block

Add a `rustinel:` block so engine compatibility data survives validation and reaches `index.json`.
`rustinel.telemetry` is **required** and must list [supported channels](rustinel-support.md#2-supported-telemetry--sigma-log-source-categories) only:

```yaml
rustinel:
  telemetry: [process_creation]      # required; supported channels only
  expected_false_positive_level: low # low | medium | high (warned if missing)
  test_status: atomic                # none | atomic | manual | dynamic
```

### Full example

```yaml
title: Suspicious Encoded PowerShell Command Line
id: 7f3a1c2e-4b5d-4e6f-8a90-1b2c3d4e5f60
status: stable
description: >
  Detects PowerShell executed with an encoded command (-EncodedCommand / -enc),
  a common technique used to obfuscate malicious payloads.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: rustinel-rules
date: 2026-06-03
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense-evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_flag:
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
      - ' -ec '
  condition: selection_img and selection_flag
falsepositives:
  - Legitimate administration tooling occasionally uses encoded commands.
level: high
rustinel:
  telemetry:
    - process_creation
  expected_false_positive_level: low
  test_status: atomic
```

Then add the `id` to a pack, e.g. `packs/windows/essential/pack.yml`:

```yaml
rules:
  has:
    sigma:
      - 7f3a1c2e-4b5d-4e6f-8a90-1b2c3d4e5f60   # Suspicious Encoded PowerShell Command Line
```

---

## YARA rules

Place the rule in `rules/yara/<os>/` as a `.yar` file. Set a stable `meta: id` (validation/build
fall back to the rule name if absent) and an `attack` technique so pack `attack_coverage` drift
checks can see it. Declare `telemetry = "file_scan"` since YARA runs on the process-creation scan.

```yara
rule win_susp_mimikatz_strings
{
    meta:
        id = "yara-win-mimikatz-strings"
        description = "Detects characteristic Mimikatz credential-dumping strings."
        author = "rustinel-rules"
        reference = "https://attack.mitre.org/software/S0002/"
        attack = "T1003.001"
        level = "high"
        os = "windows"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "manual"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "mimikatz" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 2 of ($s*)
}
```

Validation checks balanced braces, a `condition:` section, a resolvable id, and warns if there's no
`attack`/`reference` metadata.

---

## IOC sets

IOCs are stored as **typed sets**, not one file per indicator — a set groups related indicators (a
campaign, a tool, an infrastructure cluster) and is the unit packs reference by `id`.

1. Place the set under `rules/ioc/<os|common>/<name>.yml` (use `common` for cross-platform).
2. Give it an `id` prefixed `ioc-` (e.g. `ioc-cobaltstrike-2026q2`).
3. Add indicators under the relevant type(s). Each entry is a bare value or a `{value, comment}` map.

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
    - 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  domains:
    - "*.evil.example"        # leading "*." / "." matches subdomains
  ips:
    - 198.51.100.7            # single IP or CIDR (e.g. 198.51.100.0/24)
  paths_regex:
    - '^C:\\Users\\Public\\.*\.exe$'   # matched case-insensitively
```

Validation checks each value: hashes must be hex MD5/SHA1/SHA256, IPs must parse as IP/CIDR, domains
must be well-formed, path regexes must compile, and no value may contain `;` (the flat-file
delimiter). See the [IOC schema](../schemas/ioc.schema.json) and the
[supported IOC types](rustinel-support.md#6-ioc-support).

The build flattens every referenced set into `hashes.txt` / `ips.txt` / `domains.txt` /
`paths_regex.txt`, tagging each line with its source set id for provenance.

---

## Choosing a pack level

| Level | Bar for inclusion |
| ----- | ----------------- |
| `essential` | High-confidence, low-FP, broadly applicable. Safe to enable by default. |
| `advanced` | Solid production value; may produce environment-dependent false positives. |
| `hunting` | Broad/noisy leads for analysts. Never enabled by default. |

Packs are cumulative — don't re-list a rule in Advanced if it's already in Essential; Advanced
`extends` Essential.

## Before opening a PR

```bash
uv run python tools/validate.py     # must pass (0 errors)
uv run python tools/build_packs.py  # should produce dist/ cleanly
```

For the CI checks that run on every push, see
[Detection as Code](detection-as-code.md).
