# Sigma rule lifecycle

`status` expresses the maturity of a Sigma rule within its documented detection scope.
The policy applies to production Sigma source under `rules/sigma/`. Content in `preview/`
follows the [preview register](../preview/README.md), including test-only fixtures.

| Status | Required evidence |
| --- | --- |
| `experimental` | Starting status while detection, telemetry, or benign behavior is still being characterized. Keep the rule observable within its declared scope. For `test_status: manual`, give the reason in `rustinel.test_reason` and record the manual procedure and result for review. |
| `test` | A passing, gating positive Sigma atomic on each supported platform on the [certified engine](../compatibility/engine.json). Set `rustinel.test_status: atomic`. Provide at least one representative benign near miss in `rustinel.negatives`, actionable operator guidance in `rustinel.tuning`, an expected false-positive level, author attribution, and HTTP(S) source references. Document setup and collection prerequisites, known telemetry gaps, and what the alert supports. |
| `stable` | Meet the `test` criteria. Exercise materially different supported branches or platform variants with additional atomics or positive replay where they exist. Replay at least two distinct benign near misses covering the principal risks and explain remaining benign matches in `falsepositives`. Review the cases and tuning against representative workloads for the stated scope. Use a measured benign baseline when synthetic cases leave materially uncertain noise or telemetry behavior. Resolve material gaps or narrow the documented scope before promotion. |
| `deprecated` | Retired or superseded. Keep the old ID if retaining the source for history and give a `rustinel.deprecation_reason`. Remove it from all production packs, including through inheritance, and remove its entry from the live atomic manifest. Link the replacement or migration guidance in the evidence record when available. |

Manual testing, synthetic replay, skipped tests, and `allow_failure` runs can inform review.
For production `test` and `stable`, a live atomic must exercise the real sensor and fail CI if
the expected Sigma alert is missing. A declaration like `test_status: dynamic` also falls short
of that gate. The validator checks manifest registration, script presence, and that any custom
expected alert identifies the rule by name. Atomic CI and the
[benign replay suite](../tests/replay/advanced_negatives.py) check actual outcomes. Reviewers judge
fixture realism, source relevance, prerequisite accuracy, and the scope the evidence justifies.

## Rule identity and dates

Keep the same UUID v4 for revisions of a rule and when moving it between source
directories. Give a replacement with a separate identity a new file and ID.
Use `YYYY-MM-DD` for `date` and `modified`. Update `modified` when changing
`detection`, `logsource`, or `correlation`. Metadata-only edits can retain the
existing date.

PR validation compares the rule against the base revision, including
Git-detected renames. To run that check locally, use
`uv run python tools/validate.py --base origin/main`. Review rule identity for
replacements and rewrites that Git cannot identify as renames.

## Promotion and demotion

Promote to `test` once the evidence covers the rule's supported scope and the required checks pass.
Promote to `stable` once branch coverage and benign testing support predictable behavior in
that scope. Reassess when detection logic, the engine pin, platform support, or observed false
positives change. Demote `stable` to `test` when the rule still meets the `test` criteria but
loses coverage for a material branch or needs more tuning or baseline evidence. Demote to
`experimental` when the positive atomic is no longer gating, a near miss required for `test` fails,
or the other `test` criteria cease to hold. Fix the evidence or narrow the supported scope in
the same PR if you want to retain the higher status.

When required telemetry can no longer produce a match, move the content to `preview/` with
the blocker recorded, or retire it. Review pack placement and any automated response using the
affected rule as part of the same change. Mark permanently retired content `deprecated` if retaining
its source. A revived rule starts at `experimental` and earns its status on the current pin.

## Pack tier and response

Follow [#44's evidence rules](https://github.com/Karib0u/rustinel-rules/issues/44) for pack placement.
New rules enter Advanced or Hunting. Essential needs passing positive and negative evidence on
the certified engine and broadly applicable, low-noise behavior. Advanced requires tuning and
negative examples even for `experimental` rules. Hunting can carry broader, observable leads
with firing evidence, including documented manual evidence where necessary. Assign each rule
status on its own evidence and use the pack tier to decide where it ships and who should enable it.

Hunting has `active_response_eligible: false`. The catalog derives rule eligibility from pack
membership, so a rule present in both Hunting and an eligible pack is eligible via the latter.
Operators configure response separately. Review the alert's evidence, remaining false positives,
and target attribution before enabling automation. Keep manual-only rules and leads with
insufficient attribution for analyst review.

## Evidence record for pull requests

Add one record per changed rule in the PR description. Link artifacts or CI reports that a reviewer
can access. Mark any inapplicable item and explain why.

- [ ] Rule ID, previous and proposed status, reason for the change, and supported detection scope.
- [ ] Certified engine version and revision, positive atomic names and CI run for each supported
  platform, plus branch or variant coverage when claiming `stable`. For a demotion, link the
  failed or invalidated evidence and say what would restore it.
- [ ] Benign replay or atomic cases and outcomes, expected false-positive level, remaining known
  matches, and the exact tuning fields or filters. For `stable`, record the representative workloads
  reviewed and the baseline results where needed.
- [ ] Platform prerequisites such as OS features, audit policy, providers, privileges, or runner
  constraints. Record unavailable, conditional, or lossy fields and what behavior lies outside scope.
- [ ] Provenance and references that substantiate the behavior, with attribution and license details
  for adapted content.
- [ ] Resulting pack membership and response eligibility, with any needed changes to response usage.
  For retirement, include the reason and any replacement or migration guidance.

See the [corpus assessment](status-assessment.md) for examples and outstanding evidence.
