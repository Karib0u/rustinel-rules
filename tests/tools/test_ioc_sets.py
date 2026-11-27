"""Check the first production IOC sets against the pack and engine contracts."""

import sys
import tempfile
import unittest
import zipfile
from copy import copy
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import build_packs  # noqa: E402
import lib  # noqa: E402
import validate  # noqa: E402

DRIVERS = "ioc-loldrivers-vulnerable-hashes"
POOLS = "ioc-cryptomining-pools"


class IocSetsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = {artifact.id: artifact for artifact in lib.load_all_artifacts()}
        cls.packs = lib.packs_by_id()
        cls.schema = staticmethod(validate.load_schema_validator(lib.IOC_SCHEMA_PATH))

    def test_shipped_sets_pass_schema_and_value_validation(self):
        self.assertIsNotNone(self.schema)
        for set_id, ioc_type in ((DRIVERS, "hashes"), (POOLS, "domains")):
            with self.subTest(set_id=set_id):
                artifact = self.artifacts[set_id]
                report = validate.Report()
                validate.check_ioc_set(artifact, report, self.schema)
                self.assertEqual(report.errors + report.warnings, [])
                self.assertEqual(set(artifact.meta["indicators"]), {ioc_type})
                entries = artifact.indicators[ioc_type]
                values = {value for value, _ in entries}
                self.assertEqual(len(values), len(entries))
                for value, comment in entries:
                    self.assertTrue(comment)
                    if ioc_type == "hashes":
                        self.assertRegex(value, r"^[0-9a-f]{64}$")
                    else:
                        self.assertFalse(value.startswith(("*", ".")))

    def test_schema_rejects_malformed_minimum_engine(self):
        invalid = copy(self.artifacts[DRIVERS])
        invalid.meta = {**invalid.meta, "min_engine": "1.9"}
        report = validate.Report()
        validate.check_ioc_set(invalid, report, self.schema)
        self.assertIn("schema: min_engine:", "\n".join(report.errors))

    def test_ioc_telemetry_contributes_to_pack_requirements(self):
        driver_floor = lib.pack_min_engine([DRIVERS], self.artifacts, "windows")
        self.assertEqual(driver_floor, ("1.9.0", {DRIVERS: ["declared IOC min_engine: 1.9.0"]}))
        for platform in ("windows", "linux", "macos"):
            with self.subTest(platform=platform):
                pack = self.packs[f"{platform}-advanced"]
                resolved = lib.resolve_pack_rules(pack, self.packs)
                minimum, drivers = lib.pack_min_engine(resolved, self.artifacts, platform)
                self.assertEqual(pack["requires_rustinel"], f">={minimum}")
                self.assertNotIn(POOLS, drivers)
                self.assertEqual(DRIVERS in drivers, platform == "windows")

    def test_advanced_packs_flatten_only_their_iocs_with_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory) / "dist"
            dist.mkdir()
            with patch.object(lib, "DIST_DIR", dist):
                for platform in ("windows", "linux", "macos"):
                    with self.subTest(platform=platform):
                        pack_id = f"{platform}-advanced"
                        result = build_packs.materialize_pack(
                            self.packs[pack_id], self.packs, self.artifacts, lib.release_version()
                        )
                        ioc = dist / pack_id / "ioc"
                        self.assertEqual(
                            {file.name for file in ioc.glob("*.txt")},
                            {"hashes.txt", "domains.txt", "ips.txt", "paths_regex.txt"},
                        )
                        expected = {
                            "hashes": self.feed(DRIVERS, "hashes") if platform == "windows" else [],
                            "domains": self.feed(POOLS, "domains"),
                            "ips": [],
                            "paths_regex": [],
                        }
                        for kind, lines in expected.items():
                            contents = (ioc / f"{kind}.txt").read_text().splitlines()
                            self.assertEqual(
                                [line for line in contents if not line.startswith("#")], lines
                            )
                        self.assertEqual(result["ioc_count"], sum(map(len, expected.values())))
                        with zipfile.ZipFile(dist / result["artifact"]) as archive:
                            self.assertEqual(
                                "LICENSES/Apache-2.0.txt" in archive.namelist(),
                                platform == "windows",
                            )
                        essential = self.packs[f"{platform}-essential"]
                        essential_ids = lib.resolve_pack_rules(essential, self.packs)
                        self.assertTrue({DRIVERS, POOLS}.isdisjoint(essential_ids))

    def feed(self, set_id, kind):
        return [
            f"{value};[{set_id}] {comment}"
            for value, comment in self.artifacts[set_id].indicators[kind]
        ]


if __name__ == "__main__":
    unittest.main()
