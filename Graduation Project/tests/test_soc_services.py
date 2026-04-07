from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from src.desktop_services import (
    _read_log_file_content,
    analyze_soc_log,
    generate_analyst_brief,
    load_soc_log_inputs,
)
from src.pipeline import run


class AnalyzeSocLogWrapperTests(unittest.TestCase):
    def test_success_path_returns_ok_summary_and_result(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertTrue(payload["ok"])
        self.assertIn("summary", payload)
        self.assertIn("result", payload)
        summary = payload["summary"]
        self.assertIn("technique_id", summary)
        self.assertIn("technique_name", summary)
        self.assertIn("confidence", summary)
        self.assertIn("mapping_source", summary)
        self.assertIn("entity_count", summary)
        self.assertEqual(summary["mapping_source"], "rule")

    def test_exception_path_returns_ok_false_and_error(self) -> None:
        with patch("src.desktop_services.run", side_effect=RuntimeError("boom")):
            payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "boom")

    def test_no_rule_no_model_failure_is_handled(self) -> None:
        with self.assertRaises(ValidationError):
            run("benign activity with no indicators")
        payload = analyze_soc_log("benign activity with no indicators")
        self.assertFalse(payload["ok"])
        self.assertIn("No ATT&CK mapping could be produced", payload["error"])
        self.assertEqual(payload.get("reason"), "no_mapping")
        self.assertIn("summary", payload)
        self.assertIn("result", payload)
        self.assertIn("partial_result", payload)
        self.assertIn("details", payload)

    def test_no_mapping_can_return_partial_extraction_context(self) -> None:
        payload = analyze_soc_log("authentication failed user=alice src_ip=10.0.0.5")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload.get("reason"), "no_mapping")
        self.assertEqual(payload.get("summary", {}).get("technique_id"), "N/A")
        self.assertEqual(payload.get("summary", {}).get("mapping_source"), "none")
        partial = payload.get("partial_result", {})
        self.assertIsInstance(partial, dict)
        self.assertGreaterEqual(int(partial.get("audit", {}).get("entity_count", 0) or 0), 1)
        entities = partial.get("entities", [])
        self.assertTrue(any(item.get("type") == "username" and item.get("value") == "alice" for item in entities))
        self.assertEqual(payload.get("result"), partial)


class AnalystBriefMappedTests(unittest.TestCase):
    def test_mapped_brief_mentions_technique_id_and_name(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertTrue(payload["ok"])
        brief = payload.get("analyst_brief", "")
        self.assertIn("T1059", brief)
        self.assertIn("Command and Scripting Interpreter", brief)

    def test_mapped_brief_mentions_evidence(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        brief = payload.get("analyst_brief", "")
        self.assertIn("evidence", brief.lower())

    def test_mapped_brief_includes_entities_when_present(self) -> None:
        log = (
            "failed login user=alice src_ip=10.10.10.20; "
            "login failed user=alice src_ip=10.10.10.20; "
            "invalid credentials user=alice src_ip=10.10.10.20"
        )
        payload = analyze_soc_log(log)
        brief = payload.get("analyst_brief", "")
        self.assertIn("alice", brief)

    def test_mapped_brief_ends_with_recommended_action(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        brief = payload.get("analyst_brief", "")
        self.assertIn("Recommended first action:", brief)

    def test_mapped_brief_mentions_confidence(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        brief = payload.get("analyst_brief", "")
        self.assertIn("confidence", brief.lower())

    def test_brute_force_brief_mentions_t1110(self) -> None:
        log = (
            "failed login user=bob src_ip=9.9.9.9; "
            "login failed user=bob src_ip=9.9.9.9; "
            "invalid credentials user=bob src_ip=9.9.9.9"
        )
        payload = analyze_soc_log(log)
        brief = payload.get("analyst_brief", "")
        self.assertIn("T1110", brief)
        self.assertIn("Brute Force", brief)


class AnalystBriefNoMappingTests(unittest.TestCase):
    def test_no_mapping_brief_states_no_mapping(self) -> None:
        payload = analyze_soc_log("benign activity with no indicators")
        brief = payload.get("analyst_brief", "")
        self.assertIn("no mitre att&ck mapping", brief.lower())

    def test_no_mapping_brief_mentions_extracted_entities(self) -> None:
        payload = analyze_soc_log("authentication failed user=alice src_ip=10.0.0.5")
        brief = payload.get("analyst_brief", "")
        self.assertIn("alice", brief)

    def test_no_mapping_brief_suggests_next_action(self) -> None:
        payload = analyze_soc_log("benign activity with no indicators")
        brief = payload.get("analyst_brief", "")
        self.assertIn("Recommended action:", brief)

    def test_no_mapping_with_no_entities_says_so(self) -> None:
        payload = analyze_soc_log("completely empty nothing here")
        brief = payload.get("analyst_brief", "")
        self.assertTrue(
            "no entities" in brief.lower() or "no technique pattern" in brief.lower()
        )


class AnalystBriefFunctionDirectTests(unittest.TestCase):
    def test_generate_brief_with_full_mapped_payload(self) -> None:
        payload = {
            "ok": True,
            "summary": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "confidence": 0.88,
                "mapping_source": "rule",
                "entity_count": 2,
            },
            "result": {
                "entities": [
                    {"type": "username", "value": "alice", "evidence_ref": "alice"},
                    {"type": "ipv4", "value": "10.0.0.5", "evidence_ref": "10.0.0.5"},
                ],
                "attack_mapping": [
                    {
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                        "confidence": 0.88,
                        "rationale": "Multiple failed authentication attempts observed.",
                        "evidence_refs": ["failed login", "failed login"],
                    }
                ],
                "epc": {
                    "explain": "Auth failure sequence.",
                    "plan": ["Lock the account and investigate source IP."],
                    "checklist": ["Verify lockout", "Check MFA"],
                    "confidence": 0.88,
                    "citations": ["failed login"],
                },
                "audit": {"mapping_source": "rule"},
            },
        }
        brief = generate_analyst_brief(payload)
        self.assertIn("T1110", brief)
        self.assertIn("Brute Force", brief)
        self.assertIn("alice", brief)
        self.assertIn("Recommended first action:", brief)

    def test_generate_brief_with_ml_fallback_warns_analyst(self) -> None:
        payload = {
            "ok": True,
            "summary": {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "confidence": 0.7,
                "mapping_source": "ml_fallback",
                "entity_count": 0,
            },
            "result": {
                "entities": [],
                "attack_mapping": [
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "confidence": 0.7,
                        "rationale": "ML fallback prediction.",
                        "evidence_refs": ["ml_prediction"],
                    }
                ],
                "epc": {
                    "explain": "ML prediction.",
                    "plan": ["Validate prediction."],
                    "checklist": ["Check rule gap", "Record outcome"],
                    "confidence": 0.7,
                    "citations": ["ml_prediction"],
                },
                "audit": {"mapping_source": "ml_fallback"},
            },
        }
        brief = generate_analyst_brief(payload)
        self.assertIn("ML fallback", brief)
        self.assertIn("analyst review required", brief)

    def test_generate_brief_with_empty_payload_returns_no_mapping(self) -> None:
        brief = generate_analyst_brief({})
        self.assertIn("no mitre att&ck mapping", brief.lower())

    def test_generate_brief_with_low_confidence_warns(self) -> None:
        payload = {
            "ok": True,
            "summary": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "confidence": 0.3,
                "mapping_source": "rule",
                "entity_count": 1,
            },
            "result": {
                "entities": [{"type": "ipv4", "value": "1.2.3.4", "evidence_ref": "1.2.3.4"}],
                "attack_mapping": [
                    {
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                        "confidence": 0.3,
                        "rationale": "Partial evidence.",
                        "evidence_refs": ["failed login"],
                    }
                ],
                "epc": {
                    "explain": "Low conf.",
                    "plan": ["Check."],
                    "checklist": ["A", "B"],
                    "confidence": 0.3,
                    "citations": ["x"],
                },
                "audit": {"mapping_source": "rule"},
            },
        }
        brief = generate_analyst_brief(payload)
        self.assertIn("low confidence", brief.lower())


class FileInputTests(unittest.TestCase):
    def test_load_soc_log_inputs_uses_raw_text_when_no_file(self) -> None:
        output = load_soc_log_inputs("  raw log text  ", None)
        self.assertEqual(output, "raw log text")

    def test_read_log_file_content_json_raw_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "event.json"
            path.write_text('{"raw_log": "json raw log value", "other": 1}', encoding="utf-8")
            output = _read_log_file_content(str(path))
        self.assertEqual(output, "json raw log value")

    def test_read_log_file_content_plain_text_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "event.log"
            path.write_text("plain text log line", encoding="utf-8")
            output = _read_log_file_content(str(path))
        self.assertEqual(output, "plain text log line")

    def test_load_soc_log_inputs_with_file_path_reads_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "event.log"
            path.write_text(" file text value ", encoding="utf-8")
            output = load_soc_log_inputs("raw text", str(path))
        self.assertEqual(output, "file text value")

    def test_load_soc_log_inputs_prefers_file_over_raw_text_when_file_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "event.log"
            path.write_text("file wins", encoding="utf-8")
            output = load_soc_log_inputs("raw should not win", str(path))
        self.assertEqual(output, "file wins")


if __name__ == "__main__":
    unittest.main()
