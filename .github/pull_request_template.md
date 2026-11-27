## Summary

- 

- [ ] PR has a changelog label (see CONTRIBUTING.md).

## Validation

- [ ] `uv run ruff check tools`
- [ ] `uv run ruff format --check tools`
- [ ] `uv run ty check`
- [ ] `uv run python tools/validate.py`
- [ ] `uv run python tools/build_packs.py`

## Detection content checklist

- [ ] Rule ids are stable and unique.
- [ ] Pack manifests reference canonical rules from `rules/`.
- [ ] ATT&CK tags and Rustinel telemetry metadata are present where relevant.
- [ ] Expected false-positive level is documented.
- [ ] Atomic or manual test coverage is documented where relevant.
- [ ] Sigma status changes include a [lifecycle evidence record](https://github.com/Karib0u/rustinel-rules/blob/main/docs/rule-lifecycle.md#evidence-record-for-pull-requests).
