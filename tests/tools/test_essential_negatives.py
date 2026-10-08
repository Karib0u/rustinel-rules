"""Every Essential Sigma rule must carry negative evidence (#44, #43)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "replay"))
import essential_negatives  # noqa: E402
import lib  # noqa: E402


def essential_sigma_files():
    packs = lib.load_packs()
    by_id = {p["id"]: p for p in packs}
    artifacts = {a.id: a for a in lib.load_all_artifacts() if a.id}
    files = set()
    for pack in packs:
        if pack.get("level") != "essential":
            continue
        for rule_id in lib.resolve_pack_rules(pack, by_id):
            artifact = artifacts[rule_id]
            if artifact.kind == "sigma":
                files.add(artifact.rel_path.rsplit("/", 1)[-1])
    return files


class EssentialNegativeTests(unittest.TestCase):
    def test_every_essential_sigma_rule_has_negative_evidence(self):
        replayed = {f for rules in essential_negatives.CASES.values() for f in rules}
        covered = replayed | set(essential_negatives.COVERED_ELSEWHERE)
        self.assertEqual(sorted(essential_sigma_files() - covered), [])

    def test_covered_elsewhere_points_at_real_files(self):
        for rule, evidence in essential_negatives.COVERED_ELSEWHERE.items():
            self.assertTrue((ROOT / evidence).is_file(), f"{rule}: {evidence}")

    def test_no_rule_is_listed_twice(self):
        replayed = {f for rules in essential_negatives.CASES.values() for f in rules}
        self.assertEqual(replayed & set(essential_negatives.COVERED_ELSEWHERE), set())

    def test_each_replayed_rule_has_a_positive_anchor_and_negatives(self):
        for platform, rules in essential_negatives.CASES.items():
            for rule, cases in rules.items():
                positives = [c for c in cases if c[0]]
                negatives = [c for c in cases if not c[0]]
                self.assertTrue(positives, f"{platform}/{rule} has no positive anchor")
                self.assertGreaterEqual(len(negatives), 2, f"{platform}/{rule}")


if __name__ == "__main__":
    unittest.main()
