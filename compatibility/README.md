# Engine field contract

`field-availability.json` is an unmodified copy of the engine's generated contract.
`engine.json` records its released engine version, exact commit and SHA-256 digest.
Validation and atomic CI read this shared pin, currently v1.11.0. The initial
baseline was v1.6.0, proposed in [#37](https://github.com/Karib0u/rustinel-rules/issues/37).
`engine.json` is the engine CI tests against; each pack's `requires_rustinel` is the
true minimum compatible version of its content. The two are independent: moving the
pin never changes a floor by itself.

Restore the vendored file from the current exact revision with one command:

```bash
uv run python tools/refresh_engine_contract.py
```

To deliberately move certification to another released engine, refresh both files
together (replace `1.11.0` with the intended version):

```bash
uv run python tools/refresh_engine_contract.py --version 1.11.0
```

The command resolves the release tag to a commit, downloads from that commit and
validates the schema before writing either file. Review the field and override
changes, run `tools/validate.py` and the full Windows/Linux/macOS atomic suite,
review any failures, then merge the pin and contract together. Schemas 1 to 3
are supported; schema 4 and later need an explicit tooling update
before they can be vendored.

Validation needs no network access. It fails on missing or unreadable files,
malformed JSON or entries, an empty entries list, unsupported schemas or a checksum
mismatch. Its output identifies the pinned version and revision. Never-populated
fields are derived from the contract, with its reason text preserved in errors.
When a field has multiple event sources, it is blocked for the whole category only
if all rows say `never`. Category-wide `*` rows block every selected field.

`tools/engine_contract.py` holds fallback overrides for Windows process fields.
Contract rows supersede the `ParentUser` override from v1.8.0 and the `LogonId`
override from v1.11.0. `LogonGuid` still relies on its override. Preview content
stays exempt from this field guard.

The v1.11.0 contract also covers the Linux `auditd` view across process and file
records. The product-less `antivirus` category shares the Defender contract rows
for events 1116 and 1117. The contract includes Security IDs collected only when
the corresponding Windows subscription is enabled. See the engine's
[Windows Security event list](https://github.com/Karib0u/rustinel/blob/v1.11.0/docs/windows-security-events.md).

## Engine version floors

From schema 2, every row records `since`: the first release with that row's
current availability (`null` predates the oldest supported release). A pack's
`requires_rustinel` floor is derived from the `since` of every field its rules
select on, taking the earliest release in which any event source populates the
field, plus the platform, channel and native event ID floors in `tools/lib.py`.
Because `since` dates the *current* guarantee, a change to an existing field's
availability can raise the derived floor.

A released contract can carry wrong `since` values. `SINCE_CORRECTIONS` in
`tools/engine_contract.py` fixes them for the pinned release only, and stops
applying when the pin moves. The v1.8.0 contract dates the rows it introduced
`1.7.1`; diffing it against the v1.7.1 contract confirms they first shipped in
1.8.0, which is also what engine `main` records.
