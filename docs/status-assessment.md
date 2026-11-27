# Sigma status assessment

The corpus at the introduction of this policy contains 125 production Sigma rules on the
[Rustinel 1.10.0 pin](../compatibility/engine.json). Counts use each rule's lowest resolved pack tier
so inherited rules are counted once.

| Lowest pack tier | Experimental | Test | Stable |
| --- | ---: | ---: | ---: |
| Essential | 30 | 0 | 1 |
| Advanced | 86 | 1 | 0 |
| Hunting | 7 | 0 | 0 |
| Total | 123 | 1 | 1 |

Of the 123 experimental rules, 114 declare `test_status: atomic` and have gating manifest
entries for their pack platforms. Nine are manual. These are inventory counts. An individual
promotion still needs current run results and review of the rule's scope.

## Existing non-experimental rules

- **Rundll32 Execution Without Standard Arguments (`test`, Windows Advanced).** The
  `windows_rundll32_no_args` atomic exercises Windows process creation. The rule has three
  benign near misses for ordinary DLL and entry point invocations and documents `ParentImage`
  tuning for rare legitimate no-argument starts. Treat the alert as a process-start signal and
  use separate telemetry to investigate subsequent injection. Stability would need broader positive
  coverage of command-line forms and a benign baseline for legitimate no-argument starts in the
  intended environments.
  [Rule](../rules/sigma/windows/proc_creation_win_susp_rundll32_no_args.yml)
- **Suspicious Encoded PowerShell Command Line (`stable`, Windows Essential).** The
  `windows_encoded_powershell` atomic exercises the ETW process-creation path. The Windows process
  replay covers whole-argument boundaries, abbreviated flags, `pwsh`, and renamed-image matching.
  The rule now also records tuning and replayable benign cases for ordinary script execution and
  text encoding. Its stable scope is identifying encoded-command arguments. Original filename
  matching depends on PE metadata enrichment. Approved installers and admin tooling can also use
  encoded commands, so any deployment that automates response needs environment-specific evidence
  beyond this suite. [Rule](../rules/sigma/windows/proc_creation_win_susp_encoded_powershell.yml),
  [Windows replay](../tests/replay/windows_process.py)

## Evidence still needed

- **Experimental Essential rules** have negative evidence tracked in the Essential replay registry
  or linked suites. Review their per-rule tuning guidance and put representative near misses into
  the lifecycle replay path before promoting. The macOS Keychain rule is one example where local
  developer-tooling noise and collection on real endpoints merit a measured benign baseline.
  [Essential replay registry](../tests/replay/essential_negatives.py),
  [Keychain rule](../rules/sigma/macos/proc_creation_macos_keychain_dump_security.yml)
- **Experimental Advanced rules** already have inline tuning and negative fixtures. Linux's
  SUID/SGID `chmod` rule also has separate positives for symbolic and octal modes. Review package
  tooling variants and the effect of best-effort `ParentImage` data on its exclusions. The macOS TCC
  rule has process positives and benign command-line examples. Its observable scope covers selected
  tools naming the database, with MDM and fleet tooling worth baselining before a stability claim.
  [Linux chmod rule](../rules/sigma/linux/proc_creation_lnx_chmod_suid.yml),
  [macOS TCC rule](../rules/sigma/macos/proc_creation_macos_tcc_db_access.yml)
- **Manual and Hunting examples.** The Windows LOLBin outbound rule has replay coverage but its live
  atomic is an allowed failure due to inconsistent Kernel-Network event delivery. It needs reliable
  live events and a gating run before promotion. The scheduled-task name Hunting rule requires the
  TaskScheduler Operational channel. It needs a live atomic and runtime benign fixtures to leave
  experimental. The channel omits task action content and commonly matches benign updaters, so it
  remains an analyst lead. [LOLBin outbound rule](../rules/sigma/windows/net_connection_win_susp_lolbin_outbound.yml),
  [Scheduled-task rule](../rules/sigma/windows/task_creation_win_hunting_scheduled_task_name.yml)
