"""Regression tests for the offline engine field contract guard."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import engine_contract  # noqa: E402
import lib  # noqa: E402
import refresh_engine_contract  # noqa: E402
import validate  # noqa: E402


def contract_row(field="Example", availability="never", reason="engine reason", **kwargs):
    return {
        "platform": "windows",
        "category": "process_creation",
        "provider": "etw",
        "source": "Kernel-Process",
        "field": field,
        "availability": availability,
        "reason": reason,
        **kwargs,
    }


def contract_bytes(entries):
    return json.dumps({"schema_version": 1, "entries": entries}).encode()


class FieldGuardTests(unittest.TestCase):
    def setUp(self):
        self.pin, self.blocked = engine_contract.load_contract()

    def check_rule(self, platform, category, field, blocked=None):
        artifact = lib.Artifact(
            "test-rule",
            "sigma",
            lib.RULES_DIR / "test.yml",
            {
                "logsource": {"product": platform, "category": category},
                "detection": {
                    "selection": [{f"{field}|contains": "value"}],
                    "condition": "selection",
                },
            },
            "",
        )
        report = validate.Report()
        validate.check_engine_field_availability(
            artifact, report, self.blocked if blocked is None else blocked
        )
        return report

    def test_production_guard_preserves_engine_reasons(self):
        for category, field, reason in (
            (
                "task_creation",
                "TaskContent",
                "TaskScheduler event 106 does not carry the task XML definition",
            ),
            (
                "image_load",
                "Signed",
                "Kernel-Process image-load events contain no Authenticode result",
            ),
            (
                "process_creation",
                "CurrentDirectory",
                "Microsoft-Windows-Kernel-Process does not expose the working directory",
            ),
        ):
            with self.subTest(category=category, field=field):
                report = self.check_rule("windows", category, field)
                self.assertFalse(report.ok())
                self.assertIn(reason, report.errors[0])

    def test_file_and_dns_aliases_use_contract_categories(self):
        for category in ("file_event", "file_create", "file_delete", "file_change", "file_rename"):
            with self.subTest(category=category):
                self.assertFalse(self.check_rule("windows", category, "SourceFilename").ok())
        # macOS DNS is captured from packets, so answers are never parsed.
        self.assertFalse(self.check_rule("macos", "dns", "QueryResults").ok())

    def test_available_fields_and_other_platforms_are_allowed(self):
        for platform, category, field in (
            ("macos", "process_creation", "ParentCommandLine"),
            ("macos", "network_connection", "DestinationHostname"),
            ("linux", "file_rename", "SourceFilename"),
            ("windows", "process_creation", "CommandLine"),
        ):
            with self.subTest(platform=platform, category=category, field=field):
                self.assertTrue(self.check_rule(platform, category, field).ok())

    def test_wildcard_contract_blocks_any_field(self):
        report = self.check_rule("windows", "pipe_created", "PipeName")
        self.assertFalse(report.ok())
        self.assertIn("named-pipe activity is not carried", report.errors[0])

    def test_new_never_row_is_used_without_a_tooling_change(self):
        blocked = engine_contract.parse_contract(contract_bytes([contract_row(field="NewField")]))
        report = self.check_rule("windows", "process_creation", "NewField", blocked)
        self.assertFalse(report.ok())
        self.assertIn("engine reason", report.errors[0])

    def test_mixed_event_availability_does_not_block_a_category(self):
        raw = contract_bytes([contract_row(), contract_row(availability="conditional")])
        blocked = engine_contract.parse_contract(raw)
        self.assertTrue(self.check_rule("windows", "process_creation", "Example", blocked).ok())

    def test_repeated_reasons_are_deduplicated(self):
        raw = contract_bytes(
            [contract_row(), contract_row(), contract_row(reason="another reason")]
        )
        blocked = engine_contract.parse_contract(raw)
        self.assertEqual(
            blocked[("windows", "process_creation")]["Example"],
            ("engine reason", "another reason"),
        )

    def test_contract_rows_supersede_overrides(self):
        # The vendored contract now has its own ParentUser row, so that override
        # no longer applies.
        self.assertTrue(self.check_rule("windows", "process_creation", "ParentUser").ok())
        for field in ("LogonId", "LogonGuid"):
            with self.subTest(field=field):
                self.assertFalse(self.check_rule("windows", "process_creation", field).ok())
                blocked = engine_contract.parse_contract(
                    contract_bytes([contract_row(field=field, availability="conditional")])
                )
                self.assertTrue(self.check_rule("windows", "process_creation", field, blocked).ok())


class SecurityChannelTests(unittest.TestCase):
    def setUp(self):
        self.collected = engine_contract.load_event_ids()

    def security_rule(self, detection, **logsource):
        return lib.Artifact(
            "security-rule",
            "sigma",
            lib.RULES_DIR / "security.yml",
            {
                "title": "t",
                "id": "security-rule",
                "status": "experimental",
                "description": "d",
                "references": ["r"],
                "author": "a",
                "level": "high",
                "tags": ["attack.persistence"],
                "logsource": {"product": "windows", "service": "security", **logsource},
                "detection": {**detection, "condition": "selection"},
                "rustinel": {"telemetry": ["security"], "expected_false_positive_level": "low"},
            },
            "",
        )

    def test_service_only_log_source_maps_to_the_security_category(self):
        self.assertEqual(
            lib.contract_category({"product": "windows", "service": "security"}), "security"
        )
        self.assertEqual(lib.contract_category({"product": "linux", "service": "security"}), "")
        self.assertEqual(lib.contract_category({"category": "registry_set"}), "registry_event")

    def test_security_and_ps_module_are_supported_channels(self):
        report = validate.Report()
        validate.check_sigma_rule(
            self.security_rule({"selection": {"EventID": 4698, "TaskContent|contains": "x"}}),
            report,
        )
        self.assertEqual(report.errors, [])
        self.assertIn("ps_module", validate.SUPPORTED_TELEMETRY)

    def test_collected_event_ids_pass_and_uncollected_ones_fail(self):
        report = validate.Report()
        validate.check_collected_event_ids(
            self.security_rule({"selection": {"EventID": [4698, "4702"]}}), report, self.collected
        )
        self.assertEqual(report.errors, [])

        report = validate.Report()
        validate.check_collected_event_ids(
            self.security_rule({"selection": {"EventID": [4698, 4769]}}), report, self.collected
        )
        self.assertEqual(len(report.errors), 1)
        self.assertIn("EventID 4769", report.errors[0])

    def test_event_ids_behind_modifiers_and_other_categories_are_not_checked(self):
        report = validate.Report()
        validate.check_collected_event_ids(
            self.security_rule({"selection": {"EventID|gt": 1}}), report, self.collected
        )
        dns = lib.Artifact(
            "dns",
            "sigma",
            lib.RULES_DIR / "dns.yml",
            {
                "logsource": {"product": "windows", "category": "dns_query"},
                "detection": {"selection": {"EventID": 22}, "condition": "selection"},
            },
            "",
        )
        validate.check_collected_event_ids(dns, report, self.collected)
        self.assertEqual(report.errors, [])

    def test_security_fields_take_their_release_floor(self):
        minimum, _ = lib.artifact_min_engine(
            self.security_rule({"selection": {"EventID": 4698, "TaskContent|contains": "x"}})
        )
        self.assertEqual(minimum, "1.8.0")

    def test_registry_sub_categories_reach_the_field_guard(self):
        blocked = {("windows", "registry_event"): {"Example": ("engine reason",)}}
        artifact = lib.Artifact(
            "registry",
            "sigma",
            lib.RULES_DIR / "registry.yml",
            {
                "logsource": {"product": "windows", "category": "registry_set"},
                "detection": {"selection": {"Example": "x"}, "condition": "selection"},
            },
            "",
        )
        report = validate.Report()
        validate.check_engine_field_availability(artifact, report, blocked)
        self.assertFalse(report.ok())


SHADOW = "1e9b4d68-2c7a-4f93-8b15-6d0a2e4c1b04"  # Volume Shadow Copy Deletion
BCDEDIT = "e86de5fe-3908-4a95-b4e8-930a93bf4555"  # Boot Recovery Tampering
SSH_KEYS = "1b2c3d4e-5f60-4172-9b83-0c1d2e3f4a51"  # Linux authorized_keys


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        _, self.blocked = engine_contract.load_contract()
        self.sigma = {a.id: a for a in lib.load_all_artifacts() if a.kind == "sigma"}

    def correlation(self, **corr):
        body = {
            "type": "temporal",
            "rules": [SHADOW, BCDEDIT],
            "group-by": ["ParentImage"],
            "timespan": "10m",
            "condition": {"gte": 2},
            **corr,
        }
        return lib.Artifact(
            "corr",
            "sigma",
            lib.RULES_DIR / "corr.yml",
            {
                "title": "t",
                "id": "corr",
                "status": "experimental",
                "description": "d",
                "references": ["r"],
                "author": "a",
                "level": "critical",
                "tags": ["attack.impact"],
                "correlation": {k: v for k, v in body.items() if v is not None},
                "rustinel": {
                    "telemetry": ["process_creation"],
                    "expected_false_positive_level": "low",
                },
            },
            "",
        )

    def errors(self, artifact):
        report = validate.Report()
        validate.check_sigma_rule(artifact, report)
        validate.check_correlation(artifact, report, self.sigma, self.blocked)
        return report.errors

    def test_valid_correlation_needs_no_logsource_or_detection(self):
        self.assertEqual(self.errors(self.correlation()), [])

    def test_temporal_without_condition_is_rejected(self):
        errors = self.errors(self.correlation(condition=None))
        self.assertEqual(len(errors), 1)
        self.assertIn("gte: 2", errors[0])

    def test_structural_errors(self):
        for corr, message in (
            ({"type": "event_cnt"}, "correlation type"),
            ({"timespan": "10min"}, "timespan"),
            ({"type": "event_count", "condition": {"field": "x"}}, "operator"),
            ({"type": "value_count", "condition": {"gte": 3}}, "needs a 'field'"),
            ({"group-by": "ParentImage"}, "group-by"),
            ({"rules": []}, "at least one rule"),
        ):
            with self.subTest(corr=corr):
                self.assertTrue(any(message in e for e in self.errors(self.correlation(**corr))))

    def test_references_must_resolve_to_one_platform(self):
        self.assertTrue(
            any("unknown Sigma rule" in e for e in self.errors(self.correlation(rules=["nope"])))
        )
        mixed = self.correlation(rules=[SHADOW, SSH_KEYS], condition={"gte": 2})
        self.assertTrue(any("mixes rules" in e for e in self.errors(mixed)))

    def test_group_by_and_telemetry_follow_the_referenced_rules(self):
        errors = self.errors(self.correlation(**{"group-by": ["CurrentDirectory"]}))
        self.assertTrue(any("never populates" in e for e in errors))
        artifact = self.correlation()
        artifact.meta["rustinel"]["telemetry"] = ["file_event"]
        self.assertTrue(any("lacks ['process_creation']" in e for e in self.errors(artifact)))

    def test_correlation_floor_is_v1_5_0(self):
        minimum, reasons = lib.artifact_min_engine(self.correlation())
        self.assertEqual(minimum, "1.5.0")
        self.assertIn("correlation", reasons[0])

    def test_pack_must_carry_every_referenced_rule(self):
        corr = self.correlation()
        index = {**{a.id: a for a in lib.load_all_artifacts()}, corr.id: corr}
        pack = {
            "__path__": str(lib.REPO_ROOT / "packs" / "windows" / "test" / "pack.yml"),
            "name": "t",
            "id": "windows-test",
            "description": "d",
            "os": "windows",
            "level": "essential",
            "pack_schema_version": 2,
            "requires_rustinel": ">=1.5.0",
            "default": False,
            "expected_false_positive_level": "low",
            "status": "experimental",
            "license": "DRL-1.1",
            "extends": [],
            "attack_coverage": [],
            "telemetry_requirements": ["process_creation"],
            "test_status": "none",
            "rules": {"has": {"sigma": [corr.id, SHADOW]}},
        }
        report = validate.Report()
        validate.check_packs([pack], list(index.values()), report)
        self.assertTrue(any(f"references '{BCDEDIT}'" in e for e in report.errors), report.errors)


class ContractLoadTests(unittest.TestCase):
    def test_invalid_contracts_fail_loudly(self):
        valid = {"schema_version": 1, "entries": [contract_row()]}
        cases = [b"", b"not json", b"{}", b"[]", b'{"schema_version": 99,"entries":[]}']
        for schema in (None, True, "1", 2, 3):
            cases.append(json.dumps({**valid, "schema_version": schema}).encode())
        for entries in (None, [], {}, [None], [{}]):
            cases.append(json.dumps({**valid, "entries": entries}).encode())
        for key, value in (("field", ""), ("availability", "sometimes"), ("reason", "")):
            row = {**contract_row(), key: value}
            cases.append(contract_bytes([row]))
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    engine_contract.parse_contract(raw)

    def test_schema_2_requires_a_release_or_null_since(self):
        for since in ("1.7.1", None):
            with self.subTest(since=since):
                raw = json.dumps(
                    {"schema_version": 2, "entries": [contract_row(since=since)]}
                ).encode()
                blocked = engine_contract.parse_contract(raw)
                self.assertIn("Example", blocked[("windows", "process_creation")])
        for row in (
            contract_row(),
            contract_row(since="v1.7.1"),
            contract_row(since="1.7"),
            contract_row(since=171),
        ):
            with self.subTest(row=row), self.assertRaises(ValueError):
                engine_contract.parse_contract(
                    json.dumps({"schema_version": 2, "entries": [row]}).encode()
                )

    def test_unreleased_schema_3_still_fails_closed(self):
        raw = json.dumps(
            {"schema_version": 3, "entries": [contract_row(since="1.9.0", view="sysmon")]}
        ).encode()
        with self.assertRaisesRegex(ValueError, "unsupported"):
            engine_contract.parse_contract(raw)

    def test_missing_contract_or_pin_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            with self.assertRaises(OSError):
                engine_contract.load_contract(contract_path=missing)
            with self.assertRaises(OSError):
                engine_contract.load_contract(pin_path=missing)

    def test_invalid_pin_and_checksum_mismatch_fail(self):
        pin = engine_contract.read_pin()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "engine.json"
            for key in ("version", "revision", "field_availability_sha256"):
                invalid = {**pin, key: "invalid"}
                path.write_text(json.dumps(invalid))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    engine_contract.load_contract(pin_path=path)
            path.write_text(json.dumps({**pin, "field_availability_sha256": "0" * 64}))
            with self.assertRaisesRegex(ValueError, "checksum differs"):
                engine_contract.load_contract(pin_path=path)

    def test_main_returns_failure_before_loading_rules_if_contract_is_invalid(self):
        for error in (ValueError("bad contract"), PermissionError("unreadable contract")):
            with (
                self.subTest(error=error),
                patch.object(engine_contract, "load_contract", side_effect=error),
                patch.object(lib, "load_all_artifacts") as artifacts,
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(validate.main(), 1)
            artifacts.assert_not_called()
            self.assertIn(f"[ERROR] engine field contract: {error}", output.getvalue())

    def test_validation_output_identifies_pinned_revision(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(validate.main(), 0)
        pin = engine_contract.read_pin()
        self.assertIn(pin["version"], output.getvalue())
        self.assertIn(pin["revision"], output.getvalue())

    def test_atomic_workflow_emits_shared_pin_for_install_steps(self):
        workflow = yaml.safe_load((REPO_ROOT / ".github/workflows/atomic.yml").read_text())
        step = next(s for s in workflow["jobs"]["atomic"]["steps"] if s.get("id") == "engine")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            result = subprocess.run(
                ["bash", "-e"],
                input=step["run"],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
                env={**os.environ, "GITHUB_OUTPUT": str(output)},
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            pin = engine_contract.read_pin()
            self.assertEqual(
                output.read_text(), f"version={pin['version']}\nrevision={pin['revision']}\n"
            )


class RefreshTests(unittest.TestCase):
    def test_refresh_uses_exact_commit_and_updates_both_files(self):
        revision = "a" * 40
        raw = contract_bytes([contract_row()])
        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory) / "field-availability.json"
            pin = Path(directory) / "engine.json"
            with (
                patch.object(engine_contract, "CONTRACT_PATH", contract),
                patch.object(engine_contract, "PIN_PATH", pin),
                patch.object(
                    refresh_engine_contract,
                    "urlopen",
                    side_effect=[
                        io.BytesIO(json.dumps({"sha": revision}).encode()),
                        io.BytesIO(raw),
                    ],
                ) as request,
                redirect_stdout(io.StringIO()),
            ):
                refresh_engine_contract.refresh("1.6.0")
            self.assertIn(revision, request.call_args_list[1].args[0])
            loaded_pin, blocked = engine_contract.load_contract(contract, pin)
            self.assertEqual(loaded_pin["revision"], revision)
            self.assertEqual(
                loaded_pin["field_availability_sha256"], hashlib.sha256(raw).hexdigest()
            )
            self.assertIn("Example", blocked[("windows", "process_creation")])

    def test_unsupported_refresh_preserves_existing_files(self):
        raw = json.loads(contract_bytes([contract_row()]))
        raw["schema_version"] = 99
        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory) / "field-availability.json"
            pin = Path(directory) / "engine.json"
            contract.write_bytes(b"original contract")
            pin.write_bytes(b"original pin")
            with (
                patch.object(engine_contract, "CONTRACT_PATH", contract),
                patch.object(engine_contract, "PIN_PATH", pin),
                patch.object(engine_contract, "read_pin", return_value=engine_contract.read_pin()),
                patch.object(
                    refresh_engine_contract,
                    "urlopen",
                    return_value=io.BytesIO(json.dumps(raw).encode()),
                ),
                self.assertRaisesRegex(ValueError, "unsupported"),
            ):
                refresh_engine_contract.refresh()
            self.assertEqual(contract.read_bytes(), b"original contract")
            self.assertEqual(pin.read_bytes(), b"original pin")


if __name__ == "__main__":
    unittest.main()
