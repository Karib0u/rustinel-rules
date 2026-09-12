"""Version propagation: one source, and no output may disagree with it.

The drift this guards against (#38) was silent — the build stamped 0.2.0 into
every artifact for a whole release cycle after v0.3.0 shipped, because the
default lived in two scripts instead of one place.
"""

import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import lib  # noqa: E402


class ReleaseVersionTests(unittest.TestCase):
    def test_matches_pyproject(self):
        declared = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]["version"]
        self.assertEqual(lib.release_version(), declared)

    def test_is_a_three_part_version(self):
        self.assertRegex(lib.release_version(), r"^\d+\.\d+\.\d+")

    def test_build_scripts_hold_no_version_default_of_their_own(self):
        for name in ("build_packs.py", "build_catalog.py"):
            with self.subTest(script=name):
                source = (REPO_ROOT / "tools" / name).read_text()
                self.assertNotIn(
                    "DEFAULT_VERSION",
                    source,
                    f"{name} reintroduced a local version default; read lib.release_version()",
                )


class TagAgreementTests(unittest.TestCase):
    """validate.py must refuse a tagged build whose tag disagrees."""

    def _run(self, **env_overrides):
        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(Path.home()),
            **env_overrides,
        }
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "validate.py")],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT / "tools"),
            env=env,
        )

    def test_matching_tag_passes(self):
        result = self._run(GITHUB_REF_TYPE="tag", GITHUB_REF_NAME=f"v{lib.release_version()}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mismatched_tag_fails(self):
        result = self._run(GITHUB_REF_TYPE="tag", GITHUB_REF_NAME="v99.0.0")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("but [project].version is", result.stdout)

    def test_untagged_build_is_unaffected(self):
        result = self._run(GITHUB_REF_TYPE="branch", GITHUB_REF_NAME="main")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
