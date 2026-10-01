# Engine field contract

`field-availability.json` is an unmodified copy of the engine's generated contract.
`engine.json` records its released engine version, exact commit and SHA-256 digest.
Validation and atomic CI read this shared pin, currently v1.8.0. The initial
baseline was v1.6.0, proposed in [#37](https://github.com/Karib0u/rustinel-rules/issues/37).
This certification version is separate from each pack's minimum supported version.

Restore the vendored file from the current exact revision with one command:

```bash
uv run python tools/refresh_engine_contract.py
```

To deliberately move certification to another released engine, refresh both files
together (replace `1.8.0` with the intended version):

```bash
uv run python tools/refresh_engine_contract.py --version 1.8.0
```

The command resolves the release tag to a commit, downloads from that commit and
validates the schema before writing either file. Review the field and override
changes, run `tools/validate.py` and the full Windows/Linux/macOS atomic suite,
review any failures, then merge the pin and contract together. Schemas 1 and 2
are supported; schema 3 (engine `main`) and later need an explicit tooling update
before they can be vendored.

Validation needs no network access. It fails on missing or unreadable files,
malformed JSON or entries, an empty entries list, unsupported schemas or a checksum
mismatch. Its output identifies the pinned version and revision. Never-populated
fields are derived from the contract, with its reason text preserved in errors.
When a field has multiple event sources, it is blocked for the whole category only
if all rows say `never`. Category-wide `*` rows block every selected field.

`tools/engine_contract.py` holds documented overrides for Windows process fields
the contract has no row for (`LogonId`, `LogonGuid`; `ParentUser` has its own row
from v1.8.0, which supersedes its override). Any future row for one of those
fields supersedes the override automatically. Do not add copies of fields already
represented by the contract. Preview content stays exempt from this field guard.

## Engine version floors

From schema 2, every row records `since`: the first release with that row's
current availability (`null` predates the oldest supported release). A pack's
`requires_rustinel` floor is derived from the `since` of every field its rules
select on, taking the earliest release in which any event source populates the
field, plus the platform baselines in `tools/lib.py`. Because `since` dates the
*current* guarantee, a field whose availability changed is dated by the change,
which can over-claim a floor but never under-claims it.

A released contract can carry wrong `since` values. `SINCE_CORRECTIONS` in
`tools/engine_contract.py` fixes them for the pinned release only, and stops
applying when the pin moves. The v1.8.0 contract dates the rows it introduced
`1.7.1`; diffing it against the v1.7.1 contract confirms they first shipped in
1.8.0, which is also what engine `main` records.
