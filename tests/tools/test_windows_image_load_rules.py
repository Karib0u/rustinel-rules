"""Unit and pack contract checks for the v1.11.0 Windows load rules."""

import sys
import unittest
from pathlib import Path

from test_powershell_rules import fires

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "replay"))

from windows_image_load import CASES, DLL_HUNTING, DRIVER_SIGNATURE, lib  # noqa: E402


class WindowsImageLoadRulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = {
            rule.path.stem: rule for rule in lib.load_all_artifacts() if rule.path.stem in CASES
        }

    def test_detection_cases(self):
        for name, cases in CASES.items():
            rule = self.rules[name]
            negatives = rule.meta["rustinel"].get("negatives", [])
            for fields, expected in cases + [(case["fields"], False) for case in negatives]:
                with self.subTest(rule=name, fields=fields):
                    self.assertEqual(fires(rule.meta["detection"], fields), expected)

    def test_signature_values_use_the_engine_string_contract(self):
        for name, rule in self.rules.items():
            detection = rule.meta["detection"]
            if "selection_unsigned" in detection:
                with self.subTest(rule=name):
                    self.assertEqual(detection["selection_unsigned"]["Signed"], "false")
        self.assertCountEqual(
            self.rules[DRIVER_SIGNATURE].meta["detection"]["selection_invalid"]["SignatureStatus"],
            ["Expired", "Revoked", "Invalid"],
        )

    def test_telemetry_and_pack_contract(self):
        packs = {pack["id"]: pack for pack in lib.load_packs()}
        essential = lib.resolve_pack_rules(packs["windows-essential"], packs)
        advanced = packs["windows-advanced"]
        hunting = packs["windows-hunting"]
        self.assertEqual(advanced["requires_rustinel"], ">=1.11.0")
        self.assertEqual(hunting["requires_rustinel"], ">=1.11.0")
        self.assertFalse(hunting["active_response_eligible"])

        for name in CASES:
            with self.subTest(rule=name):
                rule = self.rules[name]
                category = "driver_load" if name.startswith("driver_load_") else "image_load"
                self.assertEqual(
                    rule.meta["logsource"], {"category": category, "product": "windows"}
                )
                self.assertEqual(rule.meta["rustinel"]["telemetry"], [category])
                self.assertEqual(lib.artifact_min_engine(rule)[0], "1.11.0")
                self.assertEqual(rule.meta["status"], "experimental")
                self.assertNotIn(rule.id, essential)
                if name == DLL_HUNTING:
                    self.assertEqual(rule.id, "3248cbd6-6c77-4b5c-ab44-655e7fd75667")
                    self.assertIn(rule.id, hunting["rules"]["has"]["sigma"])
                    self.assertNotIn(rule.id, advanced["rules"]["has"]["sigma"])
                else:
                    self.assertIn(rule.id, advanced["rules"]["has"]["sigma"])


if __name__ == "__main__":
    unittest.main()
