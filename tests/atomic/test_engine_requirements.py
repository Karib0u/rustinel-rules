"""Regression checks for derived Rustinel engine requirements."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "tools"))
import lib  # noqa: E402


class EngineRequirementTests(unittest.TestCase):
    def test_macos_artifact_requires_first_macos_release(self):
        artifact = lib.Artifact(
            "macos-test",
            "sigma",
            Path("macos-test.yml"),
            {
                "logsource": {"product": "macos", "category": "process_creation"},
                "detection": {"selection": {"Image|endswith": "/test"}, "condition": "selection"},
            },
            "",
        )

        minimum, reasons = lib.artifact_min_engine(artifact)

        self.assertEqual(minimum, "1.1.0")
        self.assertTrue(any("macOS" in reason for reason in reasons))

    def test_pack_platform_floor_also_covers_non_sigma_content(self):
        artifact = lib.Artifact("macos-yara", "yara", Path("macos-test.yar"), {}, "")

        minimum, _ = lib.pack_min_engine([artifact.id], {artifact.id: artifact}, platform="macos")

        self.assertEqual(minimum, "1.1.0")

    def test_linux_keeps_repository_baseline(self):
        minimum, _ = lib.pack_min_engine([], {}, platform="linux")

        self.assertEqual(minimum, "1.0.2")


if __name__ == "__main__":
    unittest.main()
