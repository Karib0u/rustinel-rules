# Non-production content (`preview/`)

Detections that are technically useful but must not ship, plus fixtures that exist only for the
atomic harness. Nothing here is packaged: `tools/lib.py` scans `rules/` for canonical artifacts, so
a pack manifest cannot reference anything in this tree, and `tools/validate.py` fails the build if
one tries.

[`preview.yml`](preview.yml) is the register. Every file under `preview/` has exactly one entry
declaring its state, why it is here, and the blocking issue where one exists. The Sigma / IOC
documents themselves stay canonical and keep their `id`, so promotion is a `git mv` back into
`rules/` plus a pack reference — the identity, and any history keyed on it, survives.

| State | Meaning | Exit condition |
| ----- | ------- | -------------- |
| `telemetry-blocked` | The logic is right, but a required field is `never` populated by the engine, so the rule can never match. | The blocker lands and the field becomes available. |
| `rewrite-required` | The telemetry exists, but the detection is shaped for a different sensor. | The rule is rewritten against the fields Rustinel actually emits. |
| `test-only` | Fixture content for `tests/atomic`. Never a detection. | Never promoted. |

Preview rules are still validated: they must parse, carry the same required metadata as production
rules, and declare supported telemetry. They are excluded from pack membership, coverage counts and
the website catalog.

## Test-only fixtures and the atomic harness

`tools/build_packs.py` flattens `test-only` IOC sets into `build/fixtures/ioc/` (outside `dist/`, so
no release artifact carries them). `tests/atomic/run_atomics.py` overlays that directory onto the
staged copy of the pack under test, which is how a fixture indicator reaches the engine without ever
entering a production pack. Pass `--no-fixtures` to run the harness against production content only.
