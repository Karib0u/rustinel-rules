# Engine field contract

`field-availability.json` is an unmodified copy of the engine's generated contract.
`engine.json` records its released engine version, exact commit and SHA-256 digest.
Validation and atomic CI read this shared pin. The initial baseline is v1.6.0,
the demonstrated baseline proposed in [#37](https://github.com/Karib0u/rustinel-rules/issues/37).
This certification version is separate from each pack's minimum supported version.

Restore the vendored file from the current exact revision with one command:

```bash
uv run python tools/refresh_engine_contract.py
```

To deliberately move certification to another released engine, refresh both files
together (replace `1.6.0` with the intended version):

```bash
uv run python tools/refresh_engine_contract.py --version 1.6.0
```

The command resolves the release tag to a commit, downloads from that commit and
validates the schema before writing either file. Review the field and override
changes, run `tools/validate.py` and the full Windows/Linux/macOS atomic suite,
review any failures, then merge the pin and contract together. Future schema
versions need an explicit tooling update before they can be vendored.

Validation needs no network access. It fails on missing or unreadable files,
malformed JSON or entries, an empty entries list, unsupported schemas or a checksum
mismatch. Its output identifies the pinned version and revision. Never-populated
fields are derived from the contract, with its reason text preserved in errors.
When a field has multiple event sources, it is blocked for the whole category only
if all rows say `never`. Category-wide `*` rows block every selected field.

`tools/engine_contract.py` holds three documented overrides for Windows process
fields absent from schema 1. Any future row for one of those fields supersedes the
override automatically. Do not add copies of fields already represented by the
contract. Preview content stays exempt from this field guard.
