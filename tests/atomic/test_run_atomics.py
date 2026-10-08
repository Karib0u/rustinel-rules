"""Regression checks for atomic alert matching, without a running engine."""

import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_atomics
from run_atomics import engine_version, make_predicate, report

sys.path.insert(0, str(Path(__file__).parent / "canary"))
import make_canary  # noqa: E402


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


class NegativeFixtureTests(unittest.TestCase):
    RULE = "Microsoft Defender Tampering via Registry"

    def setUp(self):
        self.pred = lambda alert: alert.get("rule.name") == self.RULE
        self.negative = {"script": "x.ps1", "marker": "DWORD (0x00000000)"}

    def test_alert_carrying_the_marker_is_a_violation(self):
        alert = {"rule.name": self.RULE, "registry.data.strings": ["DWORD (0x00000000)"]}
        self.assertIs(run_atomics.negative_violation(self.negative, self.pred, [alert]), alert)

    def test_late_positive_duplicate_is_not_a_violation(self):
        alert = {"rule.name": self.RULE, "registry.data.strings": ["DWORD (0x00000001)"]}
        self.assertIsNone(run_atomics.negative_violation(self.negative, self.pred, [alert]))

    def test_other_rules_are_ignored(self):
        alert = {"rule.name": "Other", "registry.data.strings": ["DWORD (0x00000000)"]}
        self.assertIsNone(run_atomics.negative_violation(self.negative, self.pred, [alert]))

    def test_any_marker_in_a_list_counts(self):
        negative = {"script": "x.ps1", "marker": ["nope", "0x00000000"]}
        alert = {"rule.name": self.RULE, "d": "DWORD (0x00000000)"}
        self.assertIs(run_atomics.negative_violation(negative, self.pred, [alert]), alert)


class RegistryManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(Path(__file__).with_name("manifest.json").read_text())["tests"]

    def test_negative_scripts_exist_and_carry_markers(self):
        for test in self.manifest:
            for neg in test.get("negatives", []):
                self.assertTrue((run_atomics.ATOMICS_DIR / neg["script"]).is_file(), neg["script"])
                self.assertTrue(neg["marker"], neg["script"])

    def test_every_registry_rule_has_a_negative_fixture(self):
        for name in (
            "windows_wdigest_registry",
            "windows_defender_registry_tamper",
            "windows_run_key_persistence",
            "windows_ifeo_debugger",
            "windows_winlogon_helper",
        ):
            test = next(t for t in self.manifest if t["name"] == name)
            self.assertTrue(test.get("negatives"), name)


class ReportTests(unittest.TestCase):
    def test_version_comes_from_the_binary(self):
        binary = Path("/engine/rustinel")
        with patch.object(
            run_atomics.subprocess, "check_output", return_value="rustinel 1.6.0\n"
        ) as query:
            self.assertEqual(engine_version(binary), "1.6.0")
        query.assert_called_once_with([str(binary), "--version"], text=True, timeout=10)

    def test_reports_preserve_version_and_failure_details_on_every_platform(self):
        for platform in ("linux", "windows", "macos"):
            for status, expected_exit in (
                ("PASS", 0),
                ("FAIL (allowed)", 0),
                ("FAIL", 1),
                ("ERROR", 1),
            ):
                with (
                    self.subTest(platform=platform, status=status),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    root = Path(tmp)
                    summary = root / "summary.md"
                    result = {
                        "name": "atomic-test",
                        "engine": "sigma",
                        "status": status,
                        "expect": "rule.name equals Test Rule",
                        "action_exit": 3,
                        "action_output": "permission denied",
                    }
                    with (
                        patch.object(run_atomics, "HARNESS_ROOT", root),
                        patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}),
                    ):
                        self.assertEqual(report([result], platform, "1.6.0"), expected_exit)
                    data = json.loads((root / f"report-{platform}.json").read_text())
                    self.assertEqual(data["platform"], platform)
                    self.assertEqual(data["engine_version"], "1.6.0")
                    self.assertEqual(data["results"], [result])
                    self.assertIn("Rustinel engine version: `1.6.0`", summary.read_text())
                    self.assertIn(status, summary.read_text())

    def test_startup_failure_is_reported_with_engine_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = root / "summary.md"
            with (
                patch.object(run_atomics, "HARNESS_ROOT", root),
                patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}),
            ):
                self.assertEqual(report([], "macos", "1.6.0", engine_error="NotPermitted"), 1)
            data = json.loads((root / "report-macos.json").read_text())
            self.assertEqual(data["engine_version"], "1.6.0")
            self.assertEqual(data["engine_error"], "NotPermitted")
            self.assertIn("NotPermitted", summary.read_text())


class PackStagingTests(unittest.TestCase):
    def test_pack_dir_is_locked_down_on_windows_before_files_arrive(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "dist" / "p"
            (src / "sigma").mkdir(parents=True)
            (src / "sigma" / "r.yml").write_text("x")
            calls = []

            def fake_run(cmd, **kwargs):
                # The folder must still be empty: new files inherit the ACL.
                calls.append((cmd, sorted(Path(cmd[1]).iterdir())))

            with (
                patch.object(run_atomics, "IS_WINDOWS", True),
                patch.object(run_atomics.subprocess, "run", fake_run),
            ):
                run_atomics.setup_engine(tmp / "engine", tmp / "dist", {"id": "p"}, None, "linux")
            ((cmd, contents),) = calls
            self.assertEqual(cmd[0], "icacls")
            self.assertIn("/inheritance:r", cmd)
            self.assertIn("*S-1-5-32-544:(OI)(CI)F", cmd)
            self.assertNotIn("*S-1-5-32-545", " ".join(cmd))
            self.assertEqual(contents, [])
            self.assertTrue((tmp / "engine" / "p" / "sigma" / "r.yml").exists())

    def test_no_acl_change_off_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "dist" / "p").mkdir(parents=True)
            with (
                patch.object(run_atomics, "IS_WINDOWS", False),
                patch.object(run_atomics.subprocess, "run") as run,
            ):
                run_atomics.setup_engine(tmp / "engine", tmp / "dist", {"id": "p"}, None, "linux")
            run.assert_not_called()


class FixtureOverlayTests(unittest.TestCase):
    def test_overlays_only_common_and_current_os_rule_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            fx = tmp / "fixtures"
            for kind, scope, name in (
                ("sigma", "linux", "l.yml"),
                ("sigma", "windows", "w.yml"),
                ("yara", "common", "c.yar"),
            ):
                (fx / kind / scope).mkdir(parents=True, exist_ok=True)
                (fx / kind / scope / name).write_text("x")
            pack = tmp / "pack"
            added = run_atomics.overlay_rule_fixtures(pack, fx, "linux")
            self.assertEqual(added, 2)
            self.assertTrue((pack / "sigma" / "l.yml").exists())
            self.assertFalse((pack / "sigma" / "w.yml").exists())
            self.assertTrue((pack / "yara" / "c.yar").exists())

    def test_memory_scanning_is_enabled_in_the_generated_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "dist" / "p").mkdir(parents=True)
            with patch.object(run_atomics, "IS_WINDOWS", False):
                run_atomics.setup_engine(tmp / "engine", tmp / "dist", {"id": "p"}, None, "linux")
            config = (tmp / "engine" / "config.toml").read_text()
            self.assertIn("yara_memory_enabled = true", config)


class ManifestPolicyTests(unittest.TestCase):
    def _load(self, tests):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.json"
            path.write_text(json.dumps({"tests": tests}))
            return run_atomics.load_manifest(path)

    def test_allowed_failure_needs_a_reason(self):
        base = {"id": "i", "name": "n", "platform": "linux", "engine": "sigma", "script": "s"}
        with self.assertRaises(SystemExit):
            self._load([{**base, "allow_failure": True}])
        self._load([{**base, "allow_failure": True, "allow_failure_reason": "flaky"}])

    def test_every_allowed_failure_in_the_shipped_manifest_has_a_reason(self):
        tests = run_atomics.load_manifest(run_atomics.HARNESS_ROOT / "manifest.json")
        self.assertTrue(any(t.get("allow_failure") for t in tests))


class CanaryBlobTests(unittest.TestCase):
    """The hash IOC only matches if three things agree byte for byte.

    The generator, the base64 embedded in each atomic script, and the SHA-256
    recorded in the IOC set are three copies of the same fact. This is the check
    that keeps them one fact: regenerate with
    `uv run python tests/atomic/canary/make_canary.py` and update all three.
    """

    IOC_SET = Path(__file__).parents[2] / "preview" / "ioc" / "common" / "ioc_canary_exec.yml"
    ATOMICS = Path(__file__).parent / "atomics"

    def _recorded_hashes(self):
        return set(re.findall(r"value:\s*([0-9a-f]{64})", self.IOC_SET.read_text()))

    def _embedded(self, path, pattern):
        blobs = re.findall(pattern, path.read_text(), re.M)
        self.assertTrue(blobs, f"no base64 blob found in {path}")
        return blobs

    def test_generator_output_is_deterministic(self):
        for name, build in make_canary.TARGETS.items():
            with self.subTest(target=name):
                self.assertEqual(build(), build())

    def test_linux_atomic_embeds_the_generated_blobs(self):
        blobs = self._embedded(self.ATOMICS / "linux" / "canary_ioc.sh", r"B64='([^']+)'")
        self.assertEqual(len(blobs), 2, "expected an x86_64 and an aarch64 blob")
        for name, blob in zip(("linux-x86_64", "linux-aarch64"), blobs, strict=True):
            with self.subTest(target=name):
                decoded = base64.b64decode(blob.replace("\n", ""))
                self.assertEqual(decoded, make_canary.TARGETS[name]())
                self.assertIn(hashlib.sha256(decoded).hexdigest(), self._recorded_hashes())

    def test_windows_atomic_embeds_the_generated_blob(self):
        parts = self._embedded(
            self.ATOMICS / "windows" / "canary_ioc.ps1", r"^\s*'([A-Za-z0-9+/=]+)'"
        )
        decoded = base64.b64decode("".join(parts))
        self.assertEqual(decoded, make_canary.TARGETS["windows-x86_64"]())
        self.assertIn(hashlib.sha256(decoded).hexdigest(), self._recorded_hashes())

    def test_macos_atomic_launches_from_the_indicator_path(self):
        # macOS uses the path indicator, so the launch path is the contract.
        script = (self.ATOMICS / "macos" / "canary_ioc.sh").read_text()
        pattern = re.search(r"paths_regex:.*?value: '([^']+)'", self.IOC_SET.read_text(), re.S)
        self.assertIsNotNone(pattern)
        launched = re.search(r'^BIN="(\$DIR/[^"]+)"', script, re.M)
        self.assertIsNotNone(launched)
        directory = re.search(r"^DIR=(\S+)", script, re.M).group(1)
        path = launched.group(1).replace("$DIR", directory)
        self.assertRegex(path, pattern.group(1).replace("\\\\", "\\"))


if __name__ == "__main__":
    unittest.main()
