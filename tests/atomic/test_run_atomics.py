"""Regression checks for atomic alert matching, without a running engine."""

import json
import unittest
from pathlib import Path

from run_atomics import make_predicate


class AlertMatchingTests(unittest.TestCase):
    def setUp(self):
        manifest = json.loads(Path(__file__).with_name("manifest.json").read_text())
        test = next(t for t in manifest["tests"] if t["name"] == "windows_run_key_persistence")
        self.matches, _ = make_predicate(test, {})
        self.alert = {
            "rule.name": "Registry Run Key Persistence",
            "registry.path": (
                r"\REGISTRY\USER\S-1-5-21\Software\Microsoft\Windows"
                r"\CurrentVersion\Run\RustinelAtomicTest"
            ),
        }

    def test_matches_the_atomic_write(self):
        self.assertTrue(self.matches(self.alert))

    def test_rejects_background_run_notification(self):
        self.alert["registry.path"] = self.alert["registry.path"].replace(
            r"Run\RustinelAtomicTest", r"RunNotification\StartupTNotiSecurityHealth"
        )
        self.assertFalse(self.matches(self.alert))

    def test_rejects_another_run_value_or_value_with_same_prefix(self):
        for name in ("AnotherStartupValue", "RustinelAtomicTestOther"):
            with self.subTest(name=name):
                alert = dict(self.alert)
                alert["registry.path"] = alert["registry.path"].replace("RustinelAtomicTest", name)
                self.assertFalse(self.matches(alert))

    def test_requires_both_conditions(self):
        for field in self.alert:
            for value in (None, 42, "unrelated"):
                with self.subTest(field=field, value=value):
                    self.assertFalse(self.matches({**self.alert, field: value}))
            alert = dict(self.alert)
            del alert[field]
            self.assertFalse(self.matches(alert))

    def test_existing_single_field_expectations(self):
        for mode, target in (("equals", "EICAR test"), ("contains", "EICAR")):
            with self.subTest(mode=mode):
                matches, _ = make_predicate(
                    {"expect": {"field": "rule.description", mode: target}}, {}
                )
                self.assertTrue(matches({"rule.description": "EICAR test"}))
                self.assertFalse(matches({"rule.description": "unrelated"}))
                self.assertFalse(matches({}))

    def test_default_rule_title_matching(self):
        matches, _ = make_predicate({"id": "test-rule"}, {"test-rule": {"title": "Test Rule"}})
        self.assertTrue(matches({"rule.name": "Test Rule"}))
        self.assertFalse(matches({"rule.name": "Another Rule"}))


if __name__ == "__main__":
    unittest.main()
