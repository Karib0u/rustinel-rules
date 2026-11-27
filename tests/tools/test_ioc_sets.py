"""Check the production IOC sets against the pack and engine contracts."""

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
LOLRMM = "ioc-lolrmm-relay-domains"


class IocSetsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = {artifact.id: artifact for artifact in lib.load_all_artifacts()}
        cls.packs = lib.packs_by_id()
        cls.schema = staticmethod(validate.load_schema_validator(lib.IOC_SCHEMA_PATH))

    def test_shipped_sets_pass_schema_and_value_validation(self):
        self.assertIsNotNone(self.schema)
        for set_id, ioc_type in ((DRIVERS, "hashes"), (POOLS, "domains"), (LOLRMM, "domains")):
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
                    elif set_id == POOLS:
                        self.assertFalse(value.startswith(("*", ".")))

    def test_lolrmm_is_attributed_and_excludes_shared_infrastructure(self):
        artifact = self.artifacts[LOLRMM]
        entries = artifact.indicators["domains"]
        self.assertEqual(artifact.meta["license"], "Apache-2.0")
        self.assertGreaterEqual(len(entries), 20)
        self.assertLessEqual(len(entries), 35)
        shared_zones = (
            "amazonaws.com",
            "azurewebsites.net",
            "cloudfront.net",
            "core.windows.net",
            "pubnubapi.com",
            "servicebus.windows.net",
            "tailscale.com",
        )
        for value, comment in entries:
            with self.subTest(value=value):
                self.assertTrue(comment.startswith("LOLRMM "))
                host = value.removeprefix("*.")
                self.assertFalse(
                    any(host == zone or host.endswith("." + zone) for zone in shared_zones)
                )

    def test_lolrmm_ships_only_in_windows_and_linux_hunting(self):
        hunting_packs = {"linux-hunting", "windows-hunting"}
        self.assertEqual(
            {
                pack_id
                for pack_id, pack in self.packs.items()
                if LOLRMM in lib.resolve_pack_rules(pack, self.packs)
            },
            hunting_packs,
        )
        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory)
            with patch.object(lib, "DIST_DIR", dist):
                for pack_id in sorted(hunting_packs):
                    with self.subTest(pack_id=pack_id):
                        result = build_packs.materialize_pack(
                            self.packs[pack_id], self.packs, self.artifacts, lib.release_version()
                        )
                        domains = (dist / pack_id / "ioc/domains.txt").read_text().splitlines()
                        self.assertEqual(
                            [line for line in domains if not line.startswith("#")],
                            self.feed(POOLS, "domains") + self.feed(LOLRMM, "domains"),
                        )
                        with zipfile.ZipFile(dist / result["artifact"]) as archive:
                            self.assertIn("LICENSES/Apache-2.0.txt", archive.namelist())

    def test_schema_rejects_malformed_minimum_engine(self):
        invalid = copy(self.artifacts[DRIVERS])
        invalid.meta = {**invalid.meta, "min_engine": "1.9"}
        report = validate.Report()
        validate.check_ioc_set(invalid, report, self.schema)
        self.assertIn("schema: min_engine:", "\n".join(report.errors))

    def warninglist_errors(self, kind, value, *, preview=False):
        root = lib.PREVIEW_DIR if preview else lib.RULES_DIR
        artifact = lib.Artifact(
            "ioc-fixture",
            "ioc",
            root / "ioc" / "common" / "fixture.yml",
            {
                "id": "ioc-fixture",
                "description": "Fixture IOC",
                "references": ["https://example.test/indicator-report"],
                "indicators": {kind: [{"value": value, "comment": "fixture"}]},
            },
            "",
        )
        report = validate.Report()
        validate.check_ioc_set(artifact, report, self.schema)
        for error in report.errors:
            self.assertIn(artifact.rel_path, error)
        return "\n".join(report.errors)

    def test_production_warninglist_rejects_addresses_and_overlapping_cidrs(self):
        for value, match in (
            ("192.168.1.1", "192.168.0.0/16"),
            ("10.0.2.1/24", "10.0.0.0/8"),
            ("169.254.169.254", "169.254.0.0/16"),
            ("127.0.0.1", "127.0.0.0/8"),
            ("203.0.113.42", "203.0.113.0/24"),
            ("8.8.8.0/24", "8.8.8.8/32"),
            ("1.1.1.1", "1.1.1.1/32"),
            ("9.9.9.9", "9.9.9.9/32"),
            ("::1", "::1/128"),
            ("fe80::1", "fe80::/10"),
            ("2001:db8:1::/48", "2001:db8::/32"),
            ("2606:4700:4700::1111", "2606:4700:4700::1111/128"),
            ("::ffff:8.8.8.8", "8.8.8.8/32"),
        ):
            with self.subTest(value=value):
                errors = self.warninglist_errors("ips", value)
                self.assertIn(f"'{value}' overlaps warninglist network {match}", errors)

    def test_production_warninglist_rejects_apexes_and_subdomains(self):
        for value, suffix in (
            ("cloudflare.com", "cloudflare.com"),
            ("*.Distribution.CloudFront.NET", "cloudfront.net"),
            (".S3.AmazonAWS.com", "amazonaws.com"),
            ("assets.GitHubUserContent.com.", "githubusercontent.com"),
            ("example.org", "example.org"),
        ):
            with self.subTest(value=value):
                self.assertIn(
                    f"'{value}' matches warninglist suffix '{suffix}'",
                    self.warninglist_errors("domains", value),
                )

    def test_warninglist_does_not_match_near_misses_or_preview_fixtures(self):
        for domain in ("notgithub.com", "github.com.other.example", "*.ioc.example.test"):
            with self.subTest(domain=domain):
                self.assertEqual(self.warninglist_errors("domains", domain), "")
        for ip in ("8.8.8.22", "2606:4700:4700::1112"):
            with self.subTest(ip=ip):
                self.assertEqual(self.warninglist_errors("ips", ip), "")
        self.assertEqual(self.warninglist_errors("ips", "8.8.8.8", preview=True), "")
        self.assertEqual(self.warninglist_errors("domains", "github.com", preview=True), "")
        self.assertIn("invalid IP/CIDR", self.warninglist_errors("ips", "300.1.1.1", preview=True))

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
