# IOC sourcing and upkeep

Windows Advanced carries vulnerable driver hashes and mining pools.
Linux and macOS Advanced carry mining pools. Hunting inherits the corresponding
Advanced indicators where a Hunting pack exists. Windows and Linux Hunting
also carry the LOLRMM set for analyst-driven inventory. Essential promotion follows
the evidence and false-positive criteria in [#44](https://github.com/Karib0u/rustinel-rules/issues/44).

## Vulnerable Windows drivers

The driver set covers the full filtered corpus of verified vulnerable Windows
driver records at LOLDrivers commit `3fe1f4c5cf18f01953317a8850f5cefdde10123d`.
The sync reads the full-file `SHA256` field of `KnownVulnerableSamples`.
It excludes unverified and malicious-only records, malformed hashes, and exact
SHA-256 matches in the shared warninglist's optional `hashes` group. The current
warninglist supplies network and domain entries. Comments carry the sample
filename, vulnerable-driver category, available CVEs, and upstream record IDs
and revision. [Pinned LOLDrivers records](https://github.com/magicsword-io/LOLDrivers/tree/3fe1f4c5cf18f01953317a8850f5cefdde10123d/yaml)

LOLDrivers publishes the records under Apache-2.0. Pack archives include the
source attribution and Apache-2.0 license text. Retain both when redistributing
the selection. [Upstream license](https://github.com/magicsword-io/LOLDrivers/blob/3fe1f4c5cf18f01953317a8850f5cefdde10123d/LICENSE)
[Pack license text](../LICENSES/Apache-2.0.txt)

An exact hit identifies the vulnerable file bytes. Legitimate vendor utilities
can ship those same bytes. Correlate with the file path, writing process, and
load telemetry before inferring abuse or taking action. Rustinel v1.9.0 added
Windows written-file scanning for qualifying artifacts, including `.sys`.
On v1.11.0, a live write can reach the hash matcher and `driver_load` provides
separate load telemetry.

## Mining pools

The mining set is an original DRL-1.1 selection of public hostnames taken from
pool operators' connection documentation and published observations from threat
research. The rule lists the sources. The selection redistributes hostname
facts and includes original comments. See the [repository license](../LICENSE).

Use exact, verified mining endpoints to avoid matching an operator's whole
domain, including its dashboard, support pages, and other services. Rustinel
supports a leading `*.` or `.` for a suffix match, which includes the apex and
all its subdomains. Exclude shared hosting and CDN addresses such as Cloudflare
IPs, along with CIDRs and IPs obtained by resolving a pool name. This set
contains hostnames only.

A match may reflect authorized mining, a hostname in a command line, or a
browser visit when the pool and its dashboard share a hostname. Review the
process and follow-on traffic and account for approved mining before taking
action.

## Remote management services

The LOLRMM set reads the network domain fields across the catalog at commit
`0c2d56639673a232ff9d2548e16c6d045d3a1217`. It covers dedicated relay, rendezvous
and agent services, including documented remote management gateways. Each comment
names the upstream tool and record. Pack archives include the source attribution
and Apache-2.0 license text. Retain both when redistributing the selection.
[Pinned LOLRMM records](https://github.com/magicsword-io/LOLRMM/tree/0c2d56639673a232ff9d2548e16c6d045d3a1217/yaml)
[Upstream license](https://github.com/magicsword-io/LOLRMM/blob/0c2d56639673a232ff9d2548e16c6d045d3a1217/LICENSE)
[Pack license text](../LICENSES/Apache-2.0.txt)

The sync accepts exact DNS hostnames and anchored suffixes written with
`*.` or `.`. It rejects IP addresses, URLs, placeholders, and in-label
wildcards. A suffix matches the apex and its subdomains, so the sync
discards suffixes that could cover an excluded hostname or warninglist
zone. It also honors upstream network entries marked `Detection: false`.
The script lists the additional consumer, collaboration, cloud and CDN
zones, vendor marketing apexes, and incidental hosts it excludes.
TeamViewer client and routing hosts can qualify while the `teamviewer.com`
apex and suffix are excluded. [LOLRMM sync exclusions](../tools/sync_lolrmm.py)

The sync retains documented exact Action1, ScreenConnect, Syncro, and
Tactical RMM hosts where upstream supplies a broader pattern, an unsupported
pattern, or omits the hostname. It folds overlapping entries into their
covering suffix and keeps their source attribution. Most self-hosted servers
use customer-specific names. Confirm a match with process and connection
telemetry and the approved support inventory.

## False-positive guard

Validation rejects production IOC addresses or CIDRs that overlap special-use
networks or public DNS resolvers. It also rejects warninglisted domain suffixes
at the apex or below it, including indicators written with `*.` or `.` for
suffix matching. The error names the IOC set, indicator, and matching entry.
Use the original source to verify a more specific indicator outside the shared
infrastructure match.

The compact [warninglist](../tools/ioc_warninglists.json) records a pinned
selection from MISP Warninglists under CC0-1.0 and the additional sources it
uses. It runs offline and applies to `rules/ioc/`. Preview fixtures can use
reserved values for replay and atomics.

## Review and expiry

Review these sets quarterly and when a source corrects an indicator, an
endpoint closes or changes ownership, or new BYOVD abuse warrants an update.
For reported RMM gateways, verify that the original report still supports
retaining the exact name. Remove entries that have been reassigned.

To refresh a set, verify the new full commit SHA and Apache-2.0 license in the
upstream repository, then update the corresponding script's `REVISION` and
the pin in this document. Run both generators and review the YAML diff,
including attribution and any widened domain match. Update the explicit
exclusions or documented service hosts when the source evidence changes.

```sh
uv run python tools/sync_loldrivers.py --write
uv run python tools/sync_lolrmm.py --write
uv run python tools/sync_loldrivers.py --check
uv run python tools/sync_lolrmm.py --check
uv run python tools/validate.py --base origin/main
```

Each script uses Git to fetch the pinned YAML snapshot. `--check` exits
with status 1 when the generated rule differs on disk. For offline testing,
`--input` accepts a directory of upstream YAML files or one YAML or JSON
fixture containing a record or list of records. The generators preserve
handwritten rule metadata and regenerate the indicators and pinned references.
[LOLDrivers sync](../tools/sync_loldrivers.py)
[LOLRMM sync](../tools/sync_lolrmm.py)

Current builds flatten sets to the engine's text feeds. Comments preserve
provenance and alert severity comes from the engine's `ioc.default_severity`.
Expiry is handled by removing entries during review. When
[rustinel#655](https://github.com/Karib0u/rustinel/issues/655) establishes its
structured format, carry verified references, confidence, severity and
`valid_until` per indicator where supported, and keep flat output for engines
that require it.

## Verification

Build the packs with `uv run python tools/build_packs.py`. Run
`uv run python tests/replay/ioc_pools.py --engine /path/to/rustinel` with the
[certified engine](../compatibility/engine.json). CI replays positive and benign
DNS events against the Windows, Linux, and macOS Advanced mining feeds and
the Windows and Linux Hunting LOLRMM feeds without making a network request.

Replay reads recorded events and cannot hash the original files. To exercise
the production hash feed without driver binaries, run the integration test
against a disposable checkout of the certified Rustinel engine revision.
From the rules repository after building the packs, point `engine_src` at
that checkout.

```sh
engine_src=/path/to/certified/rustinel
rules_dist="$PWD/dist"
cp tests/tools/ioc_hashes.rs "$engine_src/tests/"
(cd "$engine_src" && RUSTINEL_RULES_DIST="$rules_dist" cargo test --locked --release --test ioc_hashes)
```

The test checks the published RTCore64 SHA-256, its provenance, and a one-digit
near miss. The Windows and Linux canary atomics cover live hashing with harmless
test files. Live verification of the production driver set is marked manual.
