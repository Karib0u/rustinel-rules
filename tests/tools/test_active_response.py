"""Hunting content must be machine-marked as not eligible for active response."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import lib  # noqa: E402


class ActiveResponseEligibleTests(unittest.TestCase):
    def test_hunting_defaults_to_ineligible(self):
        self.assertFalse(lib.active_response_eligible({"level": "hunting"}))

    def test_other_levels_default_to_eligible(self):
        self.assertTrue(lib.active_response_eligible({"level": "essential"}))
        self.assertTrue(lib.active_response_eligible({"level": "advanced"}))

    def test_explicit_declaration_wins(self):
        pack = {"level": "advanced", "active_response_eligible": False}
        self.assertFalse(lib.active_response_eligible(pack))

    def test_shipped_hunting_packs_declare_ineligible(self):
        hunting = [p for p in lib.load_packs() if p.get("level") == "hunting"]
        self.assertTrue(hunting)
        for pack in hunting:
            self.assertIs(pack.get("active_response_eligible"), False, pack["id"])


if __name__ == "__main__":
    unittest.main()
