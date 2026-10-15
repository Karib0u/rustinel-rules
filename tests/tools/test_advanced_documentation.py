"""Advanced Sigma rules must document tuning surfaces and negative examples (#44)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import lib  # noqa: E402
import validate  # noqa: E402


class AdvancedDocumentationTests(unittest.TestCase):
    def test_shipped_advanced_rules_pass(self):
        packs = lib.load_packs()
        rep = validate.Report()
        validate.check_advanced_documentation(packs, lib.load_all_artifacts(), rep)
        self.assertEqual(rep.errors, [])

    def test_advanced_rules_are_found(self):
        rules = lib.advanced_sigma_rules(lib.load_packs(), lib.load_all_artifacts())
        self.assertGreater(len(rules), 40)

    def test_missing_documentation_is_an_error(self):
        packs = lib.load_packs()
        artifacts = lib.load_all_artifacts()
        target = lib.advanced_sigma_rules(packs, artifacts)[0]
        rustinel = target.meta["rustinel"]
        saved = {k: rustinel.pop(k) for k in ("tuning", "negatives")}
        try:
            rep = validate.Report()
            validate.check_advanced_documentation(packs, artifacts, rep)
        finally:
            rustinel.update(saved)
        self.assertEqual(len(rep.errors), 2)

    def test_malformed_entries_are_errors(self):
        packs = lib.load_packs()
        artifacts = lib.load_all_artifacts()
        target = lib.advanced_sigma_rules(packs, artifacts)[0]
        rustinel = target.meta["rustinel"]
        saved = {k: rustinel[k] for k in ("tuning", "negatives")}
        rustinel["tuning"] = [{"surface": "Image"}]
        rustinel["negatives"] = [{"reason": "no fields"}]
        try:
            rep = validate.Report()
            validate.check_advanced_documentation(packs, artifacts, rep)
        finally:
            rustinel.update(saved)
        self.assertEqual(len(rep.errors), 2)


if __name__ == "__main__":
    unittest.main()
