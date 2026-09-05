from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from src.desktop_services import (
    CorrelationStore,
    _read_log_file_content,
    analyze_soc_log,
    correlation_store,
    generate_analyst_brief,
    generate_investigation_summary,
    load_soc_log_inputs,
)
from src.pipeline import run


class _FakeNoMappingIocModule:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, bool] | None, dict[str, str] | None]] = []

    def scan_ioc(
        self,
        value: str,
        *,
        providers: dict[str, bool] | None = None,
        api_keys: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self.calls.append((value, providers, api_keys))
        return {"ioc": value, "status": "clean", "score": 10, "providers": {}, "errors": []}


class AnalyzeSocLogWrapperTests(unittest.TestCase):
    def test_success_path_returns_ok_summary_and_result(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertTrue(payload["ok"])
        self.assertIn("summary", payload)
        self.assertIn("result", payload)
        summary = payload["summary"]
        self.assertIn("technique_id", summary)
        self.assertIn("technique_name", summary)
        self.assertIn("evidence_strength", summary)
        self.assertNotIn("confidence", summary)
        self.assertIn("mapping_source", summary)
        self.assertIn("entity_count", summary)
        self.assertEqual(summary["mapping_source"], "rule")
        self.assertEqual(payload["status"], "mapped")

    def test_exception_path_returns_ok_false_and_error(self) -> None:
        with patch("src.desktop_services.run", side_effect=RuntimeError("boom")):
            payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "boom")

    def test_no_rule_no_model_is_reported_as_no_mapping_status(self) -> None:
        # The pipeline returns an explicit ``status="no_mapping"`` result
        # (NOT a ``ValidationError``) so real validation bugs can't be
        # silently re-labeled as "no mapping" by the service layer.
        result = run("benign activity with no indicators")
        self.assertEqual(result.status, "no_mapping")
        payload = analyze_soc_log("benign activity with no indicators")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload.get("status"), "no_mapping")
        self.assertNotIn("error", payload)
        self.assertIn("summary", payload)
        self.assertIn("result", payload)

    def test_no_mapping_returns_extraction_context(self) -> None:
        payload = analyze_soc_log("authentication failed user=alice src_ip=10.0.0.5")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload.get("status"), "no_mapping")
        self.assertIsNone(payload.get("summary", {}).get("technique_id"))
        self.assertIsNone(payload.get("summary", {}).get("technique_name"))
        self.assertEqual(payload.get("summary", {}).get("mapping_source"), "none")
        result = payload.get("result", {})
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("status"), "no_mapping")
        self.assertIsNone(result.get("epc"))
        self.assertEqual(result.get("attack_mapping"), [])
        self.assertGreaterEqual(int(result.get("audit", {}).get("entity_count", 0) or 0), 1)
        entities = result.get("entities", [])
        self.assertTrue(any(item.get("type") == "username" and item.get("value") == "alice" for item in entities))

    def test_no_mapping_enrichment_enabled_adds_deduped_iocs(self) -> None:
        fake = _FakeNoMappingIocModule()
        log = (
            "authentication failed user=alice src_ip=10.0.0.5 domain=evil.example.com "
            "src_ip=10.0.0.5 domain=evil.example.com"
        )
        with patch("src.pipeline._load_ioc_enrichment_module", return_value=fake):
            payload = analyze_soc_log(
                log,
                enrich_iocs=True,
                ioc_providers={"virustotal": True},
                ioc_api_keys={"virustotal": "vt-key"},
            )

        self.assertTrue(payload["ok"])
        self.assertEqual(payload.get("status"), "no_mapping")
        audit = payload.get("result", {}).get("audit", {})
        enrichment = audit.get("ioc_enrichment", [])
        self.assertEqual([item.get("ioc") for item in enrichment], ["10.0.0.5", "evil.example.com"])
        self.assertTrue(fake.calls)
        self.assertTrue(any(call[0] == "10.0.0.5" for call in fake.calls))
        self.assertTrue(any(call[0] == "evil.example.com" for call in fake.calls))
        self.assertTrue(all(call[1] == {"virustotal": True} for call in fake.calls))
        self.assertTrue(all(call[2] == {"virustotal": "vt-key"} for call in fake.calls))
        self.assertEqual(len(fake.calls), 2)

    def test_no_mapping_enrichment_disabled_omits_ioc_enrichment(self) -> None:
        payload = analyze_soc_log(
            "authentication failed user=alice src_ip=10.0.0.5 domain=evil.example.com",
            enrich_iocs=False,
        )
        self.assertTrue(payload["ok"])
        self.assertEqual(payload.get("status"), "no_mapping")
        audit = payload.get("result", {}).get("audit", {})
        self.assertNotIn("ioc_enrichment", audit)

    def test_no_mapping_enrichment_calls_pipeline_enrichment_once(self) -> None:
        original_enrich = __import__("src.pipeline", fromlist=["_enrich_iocs"])._enrich_iocs
        with patch("src.pipeline._enrich_iocs", wraps=original_enrich) as enrich_mock:
            payload = analyze_soc_log(
                "authentication failed user=alice src_ip=10.0.0.5 domain=evil.example.com",
                enrich_iocs=True,
            )
        self.assertTrue(payload["ok"])
        self.assertEqual(payload.get("status"), "no_mapping")
        self.assertEqual(enrich_mock.call_count, 1)
        # The private source IP must be skipped, never sent to providers.
        enrichment = payload["result"]["audit"]["ioc_enrichment"]
        skipped = {item["ioc"]: item for item in enrichment if item.get("status") == "skipped"}
        self.assertIn("10.0.0.5", skipped)
        self.assertEqual(skipped["10.0.0.5"]["reason"], "private_or_reserved_ip")


class AnalystBriefMappedTests(unittest.TestCase):
    def test_mapped_brief_mentions_technique_id_and_name(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertTrue(payload["ok"])
        brief = payload.get("analyst_brief", "")
        self.assertIn("T1059", brief)
        self.assertIn("Command and Scripting Interpreter", brief)

    def test_mapped_brief_labels_mapping_source(self) -> None:
        # The compact brief prefixes the line with a short source label
        # ("Rule match" / "ML prediction") so the analyst can tell at a
        # glance whether the mapping is deterministic or model-predicted.
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        brief = payload.get("analyst_brief", "")
        self.assertTrue(
            brief.startswith("Rule match:") or brief.startswith("ML prediction:"),
            f"brief did not start with a source label: {brief!r}",
        )

    def test_mapped_brief_mentions_evidence_strength_not_confidence(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        brief = payload.get("analyst_brief", "")
        self.assertIn("evidence: strong", brief.lower())
        self.assertNotIn("confidence", brief.lower())
        self.assertNotIn("%", brief)

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
        # The no-mapping branch keeps its own "Recommended action:" line
        # (it predates the technique brief template and lives outside the
        # mapped-path template).  Either phrasing is acceptable.
        self.assertTrue(
            "Recommended action:" in brief or "Next step:" in brief,
            f"brief did not contain a next-step line: {brief!r}",
        )

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
            "status": "mapped",
            "summary": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "evidence_strength": "strong",
                "mapping_source": "rule",
                "entity_count": 2,
            },
            "result": {
                "status": "mapped",
                "entities": [
                    {"type": "username", "value": "alice", "evidence_ref": "alice"},
                    {"type": "ipv4", "value": "10.0.0.5", "evidence_ref": "10.0.0.5"},
                ],
                "attack_mapping": [
                    {
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                        "evidence_strength": "strong",
                        "rationale": "Multiple failed authentication attempts observed.",
                        "evidence_refs": ["failed login", "failed login"],
                    }
                ],
                "epc": {
                    "explain": "Auth failure sequence.",
                    "plan": ["Lock the account and investigate source IP."],
                    "checklist": ["Verify lockout", "Check MFA"],
                    "citations": ["failed login"],
                },
                "audit": {"mapping_source": "rule"},
            },
        }
        brief = generate_analyst_brief(payload)
        # The compact brief surfaces the technique id, name and evidence
        # strength as a single sentence.  Entities, rationale and next-step
        # guidance are shown elsewhere in the UI (entities panel, MITRE
        # table tooltip, summary banner) and are no longer duplicated here.
        self.assertIn("T1110", brief)
        self.assertIn("Brute Force", brief)
        self.assertIn("evidence: strong", brief)
        self.assertNotIn("%", brief)
        self.assertTrue(
            brief.startswith("Rule match:"),
            f"expected rule-source prefix, got: {brief!r}",
        )

    def test_generate_brief_with_ml_fallback_warns_analyst(self) -> None:
        payload = {
            "ok": True,
            "status": "mapped",
            "summary": {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "evidence_strength": "weak",
                "mapping_source": "ml_fallback",
                "entity_count": 0,
            },
            "result": {
                "status": "mapped",
                "entities": [],
                "attack_mapping": [
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "evidence_strength": "weak",
                        "rationale": "ML fallback prediction.",
                        "evidence_refs": ["ml_prediction"],
                    }
                ],
                "epc": {
                    "explain": "ML prediction.",
                    "plan": ["Validate prediction."],
                    "checklist": ["Check rule gap", "Record outcome"],
                    "citations": ["ml_prediction"],
                },
                "audit": {"mapping_source": "ml_fallback"},
            },
        }
        brief = generate_analyst_brief(payload)
        # ML-fallback-vs-rule provenance is conveyed through the "ML
        # prediction" prefix in the compact brief; the longer "analyst
        # review required" disclaimer now lives on the summary banner and
        # the MITRE-table source column, which were the places analysts
        # actually read it from anyway.
        self.assertTrue(
            brief.startswith("ML prediction:"),
            f"expected ml-source prefix, got: {brief!r}",
        )
        self.assertIn("T1059", brief)

    def test_generate_brief_with_empty_payload_returns_no_mapping(self) -> None:
        brief = generate_analyst_brief({})
        self.assertIn("no mitre att&ck mapping", brief.lower())

    def test_generate_brief_with_weak_evidence_says_weak(self) -> None:
        payload = {
            "ok": True,
            "status": "mapped",
            "summary": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "evidence_strength": "weak",
                "mapping_source": "rule",
                "entity_count": 1,
            },
            "result": {
                "status": "mapped",
                "entities": [{"type": "ipv4", "value": "1.2.3.4", "evidence_ref": "1.2.3.4"}],
                "attack_mapping": [
                    {
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                        "evidence_strength": "weak",
                        "rationale": "Partial evidence.",
                        "evidence_refs": ["failed login"],
                    }
                ],
                "epc": {
                    "explain": "Weak evidence.",
                    "plan": ["Check."],
                    "checklist": ["A", "B"],
                    "citations": ["x"],
                },
                "audit": {"mapping_source": "rule"},
            },
        }
        brief = generate_analyst_brief(payload)
        # The compact brief reports the evidence strength as the literal
        # word; there is no numeric confidence anywhere in the brief.
        self.assertIn("evidence: weak", brief)
        self.assertNotIn("%", brief)
        self.assertIn("T1110", brief)


class InvestigationSummaryTests(unittest.TestCase):
    def test_mapped_payload_produces_what_and_next_without_severity(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertTrue(payload["ok"])
        inv = payload.get("investigation_summary", {})
        self.assertIn("what_happened", inv)
        self.assertNotIn("severity_assessment", inv)
        self.assertIn("next_steps", inv)
        self.assertIn("T1059", inv["what_happened"])
        self.assertNotIn("%", inv["what_happened"])

    def test_no_mapping_payload_says_no_pattern(self) -> None:
        payload = analyze_soc_log("benign activity with no indicators")
        inv = payload.get("investigation_summary", {})
        self.assertIn("did not identify", inv["what_happened"].lower())

    def test_generate_investigation_summary_direct(self) -> None:
        payload = {
            "summary": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "evidence_strength": "strong",
                "mapping_source": "rule",
                "entity_count": 2,
            },
            "result": {
                "entities": [
                    {"type": "username", "value": "alice"},
                    {"type": "ipv4", "value": "10.0.0.5"},
                ],
                "attack_mapping": [{"technique_id": "T1110"}],
                "epc": {"plan": ["Lock the account."]},
                "audit": {},
            },
        }
        inv = generate_investigation_summary(payload)
        self.assertIn("brute-force", inv["what_happened"].lower())
        self.assertIn("strong evidence", inv["what_happened"])
        self.assertIn("Lock the account", inv["next_steps"])
        self.assertNotIn("severity_assessment", inv)


class CorrelationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = CorrelationStore()

    def test_repeated_ioc_produces_insight(self) -> None:
        self.store.record_ioc("8.8.8.8", "clean")
        self.store.record_ioc("8.8.8.8", "malicious")
        insights = self.store.get_ioc_insights(["8.8.8.8"])
        self.assertEqual(len(insights), 1)
        self.assertEqual(insights[0]["type"], "repeated_ioc")
        self.assertIn("2 times", insights[0]["summary"])

    def test_single_ioc_no_insight(self) -> None:
        self.store.record_ioc("8.8.8.8", "clean")
        insights = self.store.get_ioc_insights(["8.8.8.8"])
        self.assertEqual(len(insights), 0)

    def test_multi_stage_pattern_detected(self) -> None:
        self.store.record_technique("T1003", "Credential Dumping", [], "strong")
        insights = self.store.get_technique_insights("T1021")
        multi_stage = [i for i in insights if i["type"] == "multi_stage"]
        self.assertTrue(len(multi_stage) > 0)
        self.assertIn("credential", multi_stage[0]["summary"].lower())

    def test_repeated_technique_produces_insight(self) -> None:
        self.store.record_technique("T1059", "Command Interpreter", [], "moderate")
        insights = self.store.get_technique_insights("T1059")
        repeated = [i for i in insights if i["type"] == "repeated_technique"]
        self.assertEqual(len(repeated), 1)

    def test_clear_resets_store(self) -> None:
        self.store.record_ioc("8.8.8.8", "clean")
        self.store.record_technique("T1059", "test", [], "weak")
        self.store.clear()
        self.assertEqual(self.store.get_ioc_insights(["8.8.8.8"]), [])
        self.assertEqual(self.store.get_technique_insights("T1059"), [])


class AnalyzeSocLogCorrelationTests(unittest.TestCase):
    def setUp(self) -> None:
        correlation_store.clear()

    def test_success_payload_contains_correlation_and_summary(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertTrue(payload["ok"])
        self.assertIn("correlation_insights", payload)
        self.assertIn("investigation_summary", payload)
        self.assertIsInstance(payload["correlation_insights"], list)
        self.assertIsInstance(payload["investigation_summary"], dict)

    def test_no_mapping_payload_contains_correlation_and_summary(self) -> None:
        payload = analyze_soc_log("benign activity with no indicators")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "no_mapping")
        self.assertIn("correlation_insights", payload)
        self.assertIn("investigation_summary", payload)


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
