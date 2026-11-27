"""Evidence checks for production Sigma status changes."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "replay"))

import advanced_negatives  # noqa: E402

import lib  # noqa: E402
import validate  # noqa: E402


class SigmaLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.rule = lib.Artifact(
            "fixture-id",
            "sigma",
            lib.RULES_DIR / "sigma" / "linux" / "fixture.yml",
            {
                "title": "Fixture rule",
                "id": "fixture-id",
                "description": "Detect a fixture",
                "status": "test",
                "references": ["https://example.test/source"],
                "author": "Fixture contributor",
                "level": "medium",
                "tags": ["attack.t1548.001"],
                "logsource": {"product": "linux", "category": "process_creation"},
                "detection": {"selection": {"Image": "/usr/bin/fixture"}, "condition": "selection"},
                "rustinel": {
                    "telemetry": ["process_creation"],
                    "test_status": "atomic",
                    "expected_false_positive_level": "medium",
                    "tuning": [{"surface": "Image", "guidance": "Use the full path."}],
                    "negatives": [{"reason": "Different binary", "fields": {"Image": "/bin/ls"}}],
                },
            },
            "",
        )
        self.rustinel = self.rule.meta["rustinel"]
        self.atomics = {("linux", self.rule.id)}

    def errors(self, *platforms):
        report = validate.Report()
        validate.check_sigma_rule(self.rule, report)
        validate.check_sigma_lifecycle(self.rule, set(platforms), self.atomics, report)
        return "\n".join(report.errors)

    def test_test_status_accepts_evidence_independent_of_pack_tier(self):
        self.assertEqual(self.errors(), "")
        self.assertEqual(self.errors("linux"), "")

    def test_promoted_statuses_require_atomic_metadata_and_coverage_on_each_platform(self):
        for status in ("test", "stable"):
            for test_status in (None, "manual", "none", "dynamic"):
                with self.subTest(status=status, test_status=test_status):
                    self.rule.meta["status"] = status
                    self.rustinel["test_status"] = test_status
                    self.rustinel["test_reason"] = "Live test unavailable"
                    errors = self.errors("linux", "macos")
                    self.assertIn("needs rustinel.test_status: atomic", errors)
                    self.assertIn("needs a gating positive Sigma atomic on macos", errors)
                    self.assertNotIn("needs a gating positive Sigma atomic on linux", errors)

    def test_unpacked_promoted_rule_requires_an_atomic_for_its_source_platform(self):
        self.atomics.clear()
        self.assertIn("needs a gating positive Sigma atomic on linux", self.errors())

    def test_test_status_requires_usable_tuning_negatives_and_provenance(self):
        self.rustinel["tuning"] = [{"surface": "Image", "guidance": "   "}]
        self.rustinel["negatives"] = [{"reason": "No event", "fields": {}}]
        self.rustinel["expected_false_positive_level"] = "unknown"
        self.rule.meta["references"] = ["https://example.test/source", "unsupported citation"]
        self.rule.meta["author"] = "   "
        errors = self.errors()
        for message in (
            "rustinel.tuning entry",
            "rustinel.negatives entry",
            "expected_false_positive_level",
            "references with HTTP(S) source URLs",
            "author attribution",
        ):
            self.assertIn(message, errors)

        del self.rustinel["tuning"], self.rustinel["negatives"]
        errors = self.errors()
        self.assertIn("needs rustinel.tuning", errors)
        self.assertIn("needs rustinel.negatives", errors)

    def test_stable_requires_distinct_benign_cases_and_false_positive_notes(self):
        self.rule.meta["status"] = "stable"
        self.rule.meta["falsepositives"] = ["  "]
        self.rustinel["negatives"].append(
            {"reason": "Another label", "fields": {"Image": "/bin/ls"}}
        )
        errors = self.errors()
        self.assertIn("at least 2 distinct rustinel.negatives", errors)
        self.assertIn("needs falsepositives", errors)

        self.rustinel["negatives"][1]["fields"]["Image"] = "/bin/cat"
        self.rule.meta["falsepositives"] = ["Approved helper also produces this behavior."]
        self.assertEqual(self.errors(), "")

    def test_experimental_can_use_manual_evidence_with_a_reason(self):
        self.rule.meta["status"] = "experimental"
        self.rustinel["test_status"] = "manual"
        self.assertIn("needs rustinel.test_reason", self.errors())
        self.rustinel["test_reason"] = "Required platform feature unavailable"
        self.assertEqual(self.errors(), "")

    def test_unsupported_status_is_rejected(self):
        self.rule.meta["status"] = "production"
        self.assertIn("unsupported Sigma status 'production'", self.errors())

    def test_deprecated_document_must_be_unpacked_with_a_reason(self):
        self.rule.meta["status"] = "deprecated"
        errors = self.errors("linux")
        self.assertIn("needs rustinel.deprecation_reason", errors)
        self.assertIn("must be removed from all production packs", errors)
        self.rustinel["deprecation_reason"] = "Superseded by a more precise rule"
        self.assertEqual(self.errors(), "")

    def test_manifest_only_counts_gating_positives_for_the_rule(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "atomics").mkdir()
            (root / "atomics" / "fixture.sh").touch()
            good = {"id": "gating", "engine": "sigma", "platform": "linux", "script": "fixture.sh"}
            tests = [
                good,
                {**good, "id": "skipped", "skip": "No coverage"},
                {**good, "id": "allowed", "allow_failure": True},
                {**good, "id": "missing", "script": "missing.sh"},
                {**good, "id": "yara", "engine": "yara"},
                {**good, "id": "unrelated", "expect": {"field": "rule.name", "equals": "Other"}},
                {
                    **good,
                    "id": "explicit",
                    "expect": [
                        {"field": "rule.name", "equals": "Fixture rule"},
                        {"field": "process.name", "contains": "fixture"},
                    ],
                },
            ]
            (root / "manifest.json").write_text(json.dumps({"tests": tests}), encoding="utf-8")
            titles = {test["id"]: "Fixture rule" for test in tests}
            self.assertEqual(
                validate.load_gating_sigma_atomics(root, titles),
                {("linux", "gating"), ("linux", "explicit")},
            )

    def test_shipped_promoted_rules_pass_and_are_selected_for_negative_replay(self):
        artifacts = lib.load_all_artifacts()
        report = validate.Report()
        platforms = validate.check_packs(lib.load_packs(), artifacts, report)
        titles = {rule.id: rule.meta["title"] for rule in artifacts if rule.kind == "sigma"}
        atomics = validate.load_gating_sigma_atomics(validate.ATOMIC_DIR, titles)
        replayed = advanced_negatives.sigma_rules_with_required_negatives()
        replayed_ids = {rule.id for rule in replayed}
        self.assertEqual(len(replayed), len(replayed_ids))
        for rule in artifacts:
            if rule.kind != "sigma":
                continue
            validate.check_sigma_lifecycle(rule, platforms.get(rule.id, set()), atomics, report)
            if rule.meta["status"] in lib.PROMOTED_SIGMA_STATUSES:
                self.assertIn(rule.id, replayed_ids)
        self.assertEqual(report.errors, [])


if __name__ == "__main__":
    unittest.main()
