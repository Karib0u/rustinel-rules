"""Validate rule metadata and its coverage in the published catalog."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import build_catalog  # noqa: E402
import lib  # noqa: E402
import validate  # noqa: E402

RULE_ID = "9349dcee-a97b-439f-bb68-66a8f7b14116"


def sigma_rule(**overrides):
    meta = {
        "title": "Fixture rule",
        "id": RULE_ID,
        "status": "experimental",
        "description": "Detect a fixture process",
        "references": ["https://example.test/detection-source"],
        "author": "Fixture contributor",
        "level": "medium",
        "date": "2026-10-01",
        "tags": ["attack.execution", "attack.t1059.006"],
        "logsource": {"product": "linux", "category": "process_creation"},
        "detection": {"selection": {"Image": "/usr/bin/fixture"}, "condition": "selection"},
        "rustinel": {
            "telemetry": ["process_creation"],
            "expected_false_positive_level": "low",
        },
        **overrides,
    }
    return lib.Artifact(
        meta["id"], "sigma", lib.RULES_DIR / "sigma" / "linux" / "fixture.yml", meta, ""
    )


class MetadataValidationTests(unittest.TestCase):
    def errors(self, artifact):
        report = validate.Report()
        if artifact.kind == "sigma":
            validate.check_sigma_rule(artifact, report)
        elif artifact.kind == "yara":
            validate.check_yara_rule(artifact, report)
        else:
            validate.check_ioc_set(artifact, report, None)
        for message in report.errors:
            self.assertIn(artifact.rel_path, message)
        return "\n".join(report.errors)

    def test_enterprise_tactics_techniques_and_software_are_recognized(self):
        tactics = """
            reconnaissance resource-development initial-access execution persistence
            privilege-escalation defense-evasion credential-access discovery lateral-movement
            collection command-and-control exfiltration impact
        """.split()
        tags = [f"attack.{tactic}" for tactic in tactics]
        tags += ["attack.t1555", "attack.T1059.006", "attack.s0002", "cve.2020-1234"]
        self.assertEqual(self.errors(sigma_rule(tags=tags)), "")

    def test_bad_attack_tags_are_file_specific(self):
        for tag, expected in (
            ("attack.exploit", "unknown or malformed ATT&CK tag"),
            ("attack.t1059.6", "unknown or malformed ATT&CK tag"),
            ("attack.", "unknown or malformed ATT&CK tag"),
            ("attack.t9999", "unknown ATT&CK technique ID 'T9999'"),
            ("attack.t1059.999", "unknown ATT&CK technique ID 'T1059.999'"),
            ("attack.s9999", "unknown ATT&CK software ID 'S9999'"),
            ("attack.t1086", "deprecated ATT&CK ID 'T1086'. Use 'T1059.001'"),
            ("attack.t1053.001", "deprecated ATT&CK ID 'T1053.001'. Use 'T1053.002'"),
            ("attack.s0209", "deprecated ATT&CK ID 'S0209'. Use 'S0012'"),
        ):
            with self.subTest(tag=tag):
                self.assertIn(expected, self.errors(sigma_rule(tags=[tag])))
        for tags in ("attack.execution", {"attack.execution": True}, [1], ["other.tag"]):
            with self.subTest(tags=tags):
                self.assertIn("no ATT&CK tag", self.errors(sigma_rule(tags=tags)))

    def test_yara_and_ioc_use_the_same_attack_metadata(self):
        raw = """
rule test_signature {
    meta:
        attack = "T1086"
        software = "S9999"
        reference = "https://example.test/signature"
    condition:
        true
}
"""
        yara = lib.Artifact(
            "test_signature",
            "yara",
            lib.RULES_DIR / "yara" / "fixture.yar",
            lib.parse_yara_meta(raw),
            raw,
        )
        self.assertIn("deprecated ATT&CK ID 'T1086'", self.errors(yara))
        self.assertIn("unknown ATT&CK software ID 'S9999'", self.errors(yara))
        yara.meta = lib.parse_yara_meta(raw.replace('"S9999"', "42"))
        self.assertIn("unknown ATT&CK software ID '42'", self.errors(yara))
        yara.meta.update(attack="T1059.001", software="S0002")
        self.assertEqual(self.errors(yara), "")
        ioc = lib.Artifact(
            "ioc-fixture",
            "ioc",
            lib.RULES_DIR / "ioc" / "fixture.yml",
            {
                "attack": ["T9999.001"],
                "indicators": {"domains": ["ioc.example.test"]},
                "references": ["https://example.test/indicator-source"],
            },
            "",
        )
        self.assertIn("unknown ATT&CK technique ID 'T9999.001'", self.errors(ioc))

    def test_sigma_uuid_v4_is_canonical(self):
        self.assertEqual(self.errors(sigma_rule()), "")
        for bad_id in (
            RULE_ID.upper(),
            f"{{{RULE_ID}}}",
            RULE_ID.replace("-", ""),
            f"{RULE_ID} ",
            "9349dcee-a97b-139f-bb68-66a8f7b14116",
            "9349dcee-a97b-439f-7b68-66a8f7b14116",
            42,
        ):
            with self.subTest(id=bad_id):
                self.assertIn("canonical lowercase UUID v4", self.errors(sigma_rule(id=bad_id)))

    def test_production_references_apply_to_experimental_rules(self):
        for refs in (None, [], "https://example.test/source", ["http:///path"], ["https://:443"]):
            with self.subTest(refs=refs):
                self.assertIn("HTTP(S) source URLs", self.errors(sigma_rule(references=refs)))
        good = "https://example.test/source"
        self.assertIn("HTTP(S) source URLs", self.errors(sigma_rule(references=[good, "citation"])))
        self.assertEqual(self.errors(sigma_rule(references=[good, "http://example.test/wiki"])), "")

    def test_roles_are_optional_and_use_the_documented_list(self):
        rule = sigma_rule()
        self.assertEqual(self.errors(rule), "")
        rustinel = rule.meta["rustinel"]
        rustinel["roles"] = [
            "workstation",
            "server",
            "domain_controller",
            "web_server",
            "developer",
            "container_host",
        ]
        self.assertEqual(self.errors(rule), "")
        for roles in (
            None,
            [],
            "web_server",
            ["desktop"],
            ["web_server", []],
            ["server", "server"],
        ):
            with self.subTest(roles=roles):
                rustinel["roles"] = roles
                self.assertIn("rustinel.roles", self.errors(rule))

    def test_sigma_dates_are_valid_and_ordered(self):
        self.assertIn("valid YYYY-MM-DD", self.errors(sigma_rule(modified="2026-02-30")))
        self.assertIn("on or after date", self.errors(sigma_rule(modified="2026-09-30")))
        self.assertEqual(self.errors(sigma_rule(modified="2026-10-01")), "")

    def test_catalog_records_roles_and_excludes_yara_context_from_coverage(self):
        catalog = build_catalog.build_catalog(lib.release_version())
        windows = {rule["id"]: rule for rule in catalog["rules"] if rule["os"] == "windows"}
        self.assertEqual(
            windows["361d95e4-185d-46bb-b357-b71f52898f97"]["roles"], ["domain_controller"]
        )
        mimikatz = windows["yara-win-mimikatz-strings"]
        self.assertEqual(mimikatz["software"], ["S0002"])
        self.assertEqual(mimikatz["related_techniques"], ["T1003.001"])
        self.assertEqual(mimikatz["techniques"], [])
        lsass = next(tech for tech in catalog["techniques"] if tech["id"] == "T1003.001")
        self.assertNotIn(mimikatz["id"], lsass["rule_ids"])

    def test_unpacked_and_retired_rules_are_excluded_from_coverage(self):
        unpacked = sigma_rule(tags=["attack.t1059.006"])
        deprecated = sigma_rule(
            id="8e8cfead-e9c1-4d4a-be73-3b1964e5a9b0",
            status="deprecated",
            tags=["attack.t1059.001"],
        )
        packed = sigma_rule(id="b171d6d6-7d40-4324-92f7-d394a7d5ff60", tags=["attack.t1059.002"])
        pack = {"id": "fixture-pack", "rules": [deprecated.id, packed.id]}
        with (
            patch.object(lib, "load_all_artifacts", return_value=[unpacked, deprecated, packed]),
            patch.object(lib, "load_packs", return_value=[pack]),
        ):
            catalog = build_catalog.build_catalog(lib.release_version())
        self.assertEqual(catalog["counts"]["active_rules"], 1)
        self.assertEqual(catalog["packs"][0]["attack_coverage"], ["T1059.002"])
        self.assertEqual([item["id"] for item in catalog["techniques"]], ["T1059.002"])


class SigmaHistoryTests(unittest.TestCase):
    def test_base_checks_stable_ids_and_behavior_edits_across_renames(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(lib, "REPO_ROOT", Path(tmp)):
            root = Path(tmp)
            source = root / "rules" / "sigma" / "fixture.yml"
            source.parent.mkdir(parents=True)
            meta = sigma_rule(modified="2026-10-02").meta
            source.write_text(yaml.safe_dump(meta), encoding="utf-8")
            env = {
                **os.environ,
                "GIT_AUTHOR_DATE": "2026-10-02T12:00:00Z",
                "GIT_COMMITTER_DATE": "2026-10-02T12:00:00Z",
            }

            def git(*args):
                subprocess.run(["git", *args], cwd=root, env=env, check=True, capture_output=True)

            git("init", "-q")
            git("add", ".")
            git(
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-qm",
                "base",
            )
            target = source.with_name("renamed.yml")
            git("mv", str(source), str(target))

            def errors():
                target.write_text(yaml.safe_dump(meta), encoding="utf-8")
                artifact = lib.Artifact(meta["id"], "sigma", target, meta, "")
                report = validate.Report()
                validate.check_sigma_history("HEAD", [artifact], report)
                return "\n".join(report.errors)

            self.assertEqual(errors(), "")
            meta["id"] = "8e8cfead-e9c1-4d4a-be73-3b1964e5a9b0"
            self.assertIn(f"keep the existing Sigma id '{RULE_ID}'", errors())
            meta["id"] = RULE_ID
            meta["detection"]["selection"]["Image"] = "/usr/bin/changed"
            self.assertIn("update the Sigma modified date", errors())
            meta["modified"] = "2026-10-15"
            self.assertEqual(errors(), "")


if __name__ == "__main__":
    unittest.main()
