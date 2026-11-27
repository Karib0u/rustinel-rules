# IOC sourcing and upkeep

Production IOC sets enter Advanced first. Windows Advanced carries both sets.
Linux and macOS Advanced carry mining pools. Hunting inherits the corresponding
Advanced indicators where a Hunting pack exists. Essential promotion follows
the evidence and false-positive criteria in [#44](https://github.com/Karib0u/rustinel-rules/issues/44).

## Vulnerable Windows drivers

The driver set is a curated subset of LOLDrivers records for drivers associated
with bring-your-own-vulnerable-driver activity. Each full-file SHA-256 was
cross-checked against the [public feed](https://www.loldrivers.io/api/drivers.json)
and a [pinned snapshot](https://github.com/magicsword-io/LOLDrivers/tree/39c70ca64ae9b66650e2c50e011eec6f7354e9cf/yaml)
from 2026-10-27. The set lists each source record, and comments carry the sample
filename, source revision, and vulnerable-driver category or CVE. Use the
record's full-file digest field. Authenticode and PE-section hashes are computed
over different bytes.

The [upstream repository license](https://github.com/magicsword-io/LOLDrivers/blob/39c70ca64ae9b66650e2c50e011eec6f7354e9cf/LICENSE)
for these records is Apache-2.0. The selection and comments identify the source
and describe the changes from upstream. Retain that attribution and the
[Apache-2.0 license text](../LICENSES/Apache-2.0.txt) when redistributing
the selection. Pack archives carrying the set include both.

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

## Review and expiry

Review both sets quarterly and when a source corrects an indicator, a mining
endpoint closes or changes ownership, or new BYOVD abuse warrants an update.
Verify each change against a primary source, record the revision or review date,
and remove erroneous or stale entries. Initial hostname review was on
2026-11-27.

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
DNS events against the Windows, Linux, and macOS Advanced feeds without making
a network request.

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
