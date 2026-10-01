"""Regression tests for the engine install-contract check.

Each failure here is one an engine would hit in `rustinel rules install|update`
or `rustinel setup`, where a single bad pack entry rejects the whole catalog.
"""

import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import check_engine_install  # noqa: E402

IOC = ("hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt")


def manifest(pack_id="linux-essential", **overrides):
    doc = {
        "name": "Linux Essential",
        "id": pack_id,
        "description": "Test pack",
        "os": "linux",
        "level": "essential",
        "pack_schema_version": 2,
        "requires_rustinel": ">=1.0.2",
        "default": True,
        "status": "stable",
        "extends": [],
    }
    doc.update(overrides)
    return doc


def build_zip(doc, root="", ioc=IOC, extra=()):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("pack.yml", yaml.safe_dump(doc))
        zf.writestr(f"{root}sigma/rule.yml", "title: x\n")
        zf.writestr(f"{root}yara/rule.yar", "rule x { condition: false }\n")
        for name in ioc:
            zf.writestr(f"{root}ioc/{name}", "")
        for item in extra:
            zf.writestr(*item) if isinstance(item, tuple) else zf.writestr(item, "")
    return buffer.getvalue()


class DistFixture:
    """A dist/ directory with one valid pack, plus a published baseline."""

    def __init__(self, tmp: Path):
        self.dist = tmp / "dist"
        self.dist.mkdir()
        self.baseline_path = tmp / "baseline.json"
        self.catalog = {"schema": "rustinel-rules/index@1", "release_version": "0.4.0", "packs": []}
        self.baseline = {
            "schema": "rustinel-rules/index@1",
            "release_version": "0.3.1",
            "packs": [],
        }

    def add(self, pack_id="linux-essential", data=None, **entry):
        data = data if data is not None else build_zip(manifest(pack_id))
        artifact = entry.pop("artifact", f"{pack_id}-0.4.0.zip")
        if "/" not in artifact:
            (self.dist / artifact).write_bytes(data)
        pack = {
            "id": pack_id,
            "name": "Linux Essential",
            "os": "linux",
            "level": "essential",
            "version": "0.4.0",
            "default": True,
            "requires_rustinel": ">=1.0.2",
            "status": "stable",
            "artifact": artifact,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        pack.update(entry)
        self.catalog["packs"].append(pack)
        self.baseline["packs"].append(dict(pack, version="0.3.1"))
        return pack

    def run(self, *args, baseline=True):
        (self.dist / "index.json").write_text(json.dumps(self.catalog))
        self.baseline_path.write_text(json.dumps(self.baseline))
        argv = [
            "--dist",
            str(self.dist),
            "--baseline",
            str(self.baseline_path) if baseline else "none",
            *args,
        ]
        out = io.StringIO()
        with redirect_stdout(out):
            code = check_engine_install.main(argv)
        return code, out.getvalue()


class EngineInstallCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fx = DistFixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def assertFails(self, needle, *args, **kwargs):
        code, out = self.fx.run(*args, **kwargs)
        self.assertEqual(code, 1, out)
        self.assertIn(needle, out)

    def test_valid_pack_passes(self):
        self.fx.add()
        code, out = self.fx.run()
        self.assertEqual(code, 0, out)

    def test_rules_subdirectory_layout_passes(self):
        self.fx.add(data=build_zip(manifest(), root="rules/"))
        self.assertEqual(self.fx.run()[0], 0)

    def test_wrong_index_schema(self):
        self.fx.add()
        self.fx.catalog["schema"] = "rustinel-rules/index@2"
        self.assertFails("is not 'rustinel-rules/index@1'")

    def test_missing_ioc_file(self):
        self.fx.add(data=build_zip(manifest(), ioc=IOC[:3]))
        self.assertFails("missing ioc/paths_regex.txt")

    def test_missing_rule_directory(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("pack.yml", yaml.safe_dump(manifest()))
            zf.writestr("sigma/rule.yml", "")
            for name in IOC:
                zf.writestr(f"ioc/{name}", "")
        self.fx.add(data=buffer.getvalue())
        self.assertFails("needs sigma/, yara/ and ioc/")

    def test_unsafe_entry_path(self):
        self.fx.add(data=build_zip(manifest(), extra=["sigma/../../escape.yml"]))
        self.assertFails("is unsafe")

    def test_symlink_entry(self):
        link = zipfile.ZipInfo("sigma/link.yml")
        link.external_attr = 0o120777 << 16
        self.fx.add(data=build_zip(manifest(), extra=[(link, "/etc/passwd")]))
        self.assertFails("is a symlink")

    def test_manifest_requirement_must_match_catalog(self):
        self.fx.add(data=build_zip(manifest(requires_rustinel=">=1.4.1")))
        self.assertFails("does not match index.json")

    def test_manifest_required_fields_and_types(self):
        doc = manifest(default="yes")
        del doc["extends"]
        self.fx.add(data=build_zip(doc))
        code, out = self.fx.run()
        self.assertEqual(code, 1)
        self.assertIn("missing required field 'extends'", out)
        self.assertIn("'default' must be bool", out)

    def test_unsupported_pack_schema(self):
        self.fx.add(data=build_zip(manifest(pack_schema_version=3)))
        self.assertFails("pack_schema_version 3")

    def test_sha256_mismatch(self):
        self.fx.add(sha256="0" * 64)
        self.assertFails("sha256 does not match")

    def test_artifact_must_be_a_bare_zip_name(self):
        self.fx.add(artifact="packs/linux-essential.zip")
        self.assertFails("must be a .zip file name with no directory")

    def test_requirement_above_certified_engine(self):
        self.fx.add(
            data=build_zip(manifest(requires_rustinel=">=99.0.0")), requires_rustinel=">=99.0.0"
        )
        self.assertFails("does not satisfy, so CI never tested it")

    def test_removed_pack_id(self):
        self.fx.add()
        self.fx.baseline["packs"].append(dict(self.fx.baseline["packs"][0], id="windows-hunting"))
        self.assertFails("windows-hunting: was published in v0.3.1 and is missing now")

    def test_release_version_must_not_go_backwards(self):
        self.fx.add()
        self.fx.catalog["release_version"] = "0.3.0"
        self.assertFails("is older than the published v0.3.1")

    def test_unbumped_version_is_a_note_except_on_release(self):
        self.fx.add()
        self.fx.catalog["release_version"] = "0.3.1"
        code, out = self.fx.run()
        self.assertEqual(code, 0, out)
        self.assertIn("[NOTE]", out)
        self.assertFails("would not offer it", "--release")

    def test_requirement_change_is_reported(self):
        self.fx.add()
        self.fx.baseline["packs"][0]["requires_rustinel"] = ">=1.0.0"
        code, out = self.fx.run()
        self.assertEqual(code, 0, out)
        self.assertIn("requires_rustinel changes >=1.0.0 -> >=1.0.2", out)

    def test_baseline_can_be_skipped_offline(self):
        self.fx.add()
        self.fx.catalog["release_version"] = "0.0.1"
        self.assertEqual(self.fx.run(baseline=False)[0], 0)


class RequirementTests(unittest.TestCase):
    def test_accepts_the_subset_build_packs_emits(self):
        self.assertTrue(check_engine_install.requirement_matches(">=1.4.1", "1.6.0"))
        self.assertFalse(check_engine_install.requirement_matches(">=1.8.0", "1.6.0"))
        self.assertTrue(check_engine_install.requirement_matches(">=1.0.0, <2.0.0", "1.6.0"))
        self.assertFalse(check_engine_install.requirement_matches(">=1.0.0, <1.6.0", "1.6.0"))

    def test_rejects_requirements_outside_the_subset(self):
        for text in ("", "1.4.1", "^1.4", ">=1.4", ">=v1.4.1", "*"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                check_engine_install.parse_requirement(text)


if __name__ == "__main__":
    unittest.main()
