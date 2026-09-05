"""Hardening regression tests (v1).

Pins the behaviour changes that remove fabricated confidence from the SOC
workstation and stop private / internal indicators from reaching external
threat-intel providers:

* ``run()`` never raises on unmapped input — it returns an explicit
  ``status="no_mapping"`` result with no EPC and no mappings.
* ``Result`` enforces ``status`` ⇔ ``attack_mapping`` consistency.
* No ML model is auto-loaded when no explicit path is given.
* VirusTotal verdicts use vendor-count thresholds, not "any hit".
* ``compute_verdict`` yields a categorical assessment with no numeric field.
* Private / reserved / internal indicators are skipped with no HTTP call.
* EPC response plans never open with host isolation.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from pydantic import ValidationError

from src.contracts import AttackMapping, EPC, Result
from src.desktop_services import _resolve_fallback_model
from src.ioc_enrichment import (
    IOC_TYPE_IP,
    clear_scan_cache,
    compute_verdict,
    is_scannable_ioc,
    scan_ioc,
    vt_lookup,
)
from src.pipeline import _build_epc, run


def _mapping(technique_id: str = "T1059") -> AttackMapping:
    return AttackMapping(
        technique_id=technique_id,
        technique_name="Command and Scripting Interpreter",
        evidence_strength="strong",
        rationale="test",
        evidence_refs=["powershell"],
    )


def _epc() -> EPC:
    return EPC(explain="x", plan=["p"], checklist=["a", "b"], citations=["c"])


class PipelineNoMappingStatusTests(unittest.TestCase):
    def test_run_with_no_model_returns_a_status_and_never_raises(self) -> None:
        result = run("cmdline=whoami", model=None)
        self.assertIn(result.status, {"mapped", "no_mapping"})
        if result.status == "mapped":
            self.assertIsNotNone(result.epc)
            self.assertGreaterEqual(len(result.attack_mapping), 1)
        else:
            self.assertIsNone(result.epc)
            self.assertEqual(result.attack_mapping, [])

    def test_benign_web_log_is_no_mapping(self) -> None:
        result = run("nginx: GET /index.html 200", model=None)
        self.assertEqual(result.status, "no_mapping")
        self.assertIsNone(result.epc)
        self.assertEqual(result.attack_mapping, [])
        self.assertEqual(result.audit["mapping_source"], "none")
        self.assertEqual(result.audit["mapping_count"], 0)
        self.assertIn("entity_count", result.audit)
        self.assertIn("normalized_event", result.audit)
        self.assertIn("pipeline_version", result.audit)

    def test_no_mapping_audit_carries_ioc_enrichment_when_requested(self) -> None:
        with patch("src.ioc_enrichment._http_get_json", side_effect=AssertionError("no HTTP")), \
             patch("src.ioc_enrichment._http_post_json", side_effect=AssertionError("no HTTP")):
            result = run("nginx: GET /index.html 200 client=10.1.2.3", enrich_iocs=True)
        self.assertEqual(result.status, "no_mapping")
        self.assertIn("ioc_enrichment", result.audit)


class ResultContractTests(unittest.TestCase):
    def test_mapped_requires_at_least_one_mapping(self) -> None:
        with self.assertRaises(ValidationError):
            Result(status="mapped", entities=[], attack_mapping=[], epc=_epc(), audit={})

    def test_no_mapping_requires_empty_mapping(self) -> None:
        with self.assertRaises(ValidationError):
            Result(status="no_mapping", entities=[], attack_mapping=[_mapping()], epc=None, audit={})

    def test_mapped_requires_epc(self) -> None:
        with self.assertRaises(ValidationError):
            Result(status="mapped", entities=[], attack_mapping=[_mapping()], epc=None, audit={})

    def test_no_mapping_requires_epc_none(self) -> None:
        with self.assertRaises(ValidationError):
            Result(status="no_mapping", entities=[], attack_mapping=[], epc=_epc(), audit={})

    def test_consistent_results_validate(self) -> None:
        Result(status="mapped", entities=[], attack_mapping=[_mapping()], epc=_epc(), audit={})
        Result(status="no_mapping", entities=[], attack_mapping=[], epc=None, audit={})

    def test_attack_mapping_has_no_confidence_field(self) -> None:
        with self.assertRaises(ValidationError):
            AttackMapping(
                technique_id="T1059",
                technique_name="x",
                evidence_strength="strong",
                confidence=0.9,  # type: ignore[call-arg]
                rationale="r",
                evidence_refs=["e"],
            )
        with self.assertRaises(ValidationError):
            AttackMapping(
                technique_id="T1059",
                technique_name="x",
                evidence_strength="high",  # type: ignore[arg-type]
                rationale="r",
                evidence_refs=["e"],
            )


class MlNeverAutoLoadsTests(unittest.TestCase):
    def test_empty_model_path_returns_none(self) -> None:
        self.assertIsNone(_resolve_fallback_model(""))

    def test_whitespace_model_path_returns_none_without_touching_disk(self) -> None:
        with patch("src.desktop_services.load_model") as load_mock:
            self.assertIsNone(_resolve_fallback_model("   "))
        load_mock.assert_not_called()


class VirusTotalThresholdTests(unittest.TestCase):
    def _lookup(self, stats: dict[str, int]) -> dict:
        payload = {"data": {"attributes": {"last_analysis_stats": stats}}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            return vt_lookup("8.8.8.8", IOC_TYPE_IP, "key")

    def test_single_malicious_vendor_is_suspicious_not_malicious(self) -> None:
        result = self._lookup({"malicious": 1, "harmless": 60})
        self.assertEqual(result["status"], "suspicious")
        self.assertEqual(result["details"]["vendor_total"], 61)

    def test_three_malicious_vendors_is_malicious(self) -> None:
        result = self._lookup({"malicious": 3, "harmless": 60, "undetected": 7})
        self.assertEqual(result["status"], "malicious")
        self.assertEqual(result["details"]["vendor_total"], 70)

    def test_suspicious_only_is_suspicious(self) -> None:
        result = self._lookup({"malicious": 0, "suspicious": 2, "harmless": 50})
        self.assertEqual(result["status"], "suspicious")

    def test_harmless_only_is_clean(self) -> None:
        result = self._lookup({"malicious": 0, "suspicious": 0, "harmless": 50})
        self.assertEqual(result["status"], "clean")

    def test_no_vendor_data_is_unknown(self) -> None:
        result = self._lookup({})
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["details"]["vendor_total"], 0)


class ComputeVerdictAssessmentTests(unittest.TestCase):
    def _assert_no_confidence(self, verdict: dict) -> None:
        self.assertNotIn("confidence", verdict)
        self.assertNotIn("verdict", verdict)
        self.assertNotIn("score", verdict)

    def test_corroborated_malicious(self) -> None:
        verdict = compute_verdict({
            "virustotal": {"status": "malicious"},
            "abuseipdb": {"status": "malicious"},
        })
        self.assertEqual(verdict["assessment"], "corroborated_malicious")
        self.assertEqual(sorted(verdict["malicious"]), ["abuseipdb", "virustotal"])
        self._assert_no_confidence(verdict)

    def test_providers_disagree(self) -> None:
        verdict = compute_verdict({
            "virustotal": {"status": "malicious"},
            "otx": {"status": "clean"},
        })
        self.assertEqual(verdict["assessment"], "providers_disagree")
        self.assertEqual(verdict["malicious"], ["virustotal"])
        self.assertEqual(verdict["clean"], ["otx"])
        self._assert_no_confidence(verdict)

    def test_single_source_malicious(self) -> None:
        verdict = compute_verdict({
            "virustotal": {"status": "malicious"},
            "otx": {"status": "n/a"},
            "threatfox": {"status": "not_found"},
        })
        self.assertEqual(verdict["assessment"], "single_source_malicious")
        self.assertEqual(verdict["responding"], ["virustotal"])
        self._assert_no_confidence(verdict)

    def test_suspicious_only(self) -> None:
        verdict = compute_verdict({
            "virustotal": {"status": "suspicious"},
            "otx": {"status": "suspicious"},
        })
        self.assertEqual(verdict["assessment"], "suspicious_only")
        self.assertEqual(sorted(verdict["suspicious"]), ["otx", "virustotal"])
        self._assert_no_confidence(verdict)

    def test_no_suspicious_findings(self) -> None:
        verdict = compute_verdict({
            "virustotal": {"status": "clean"},
            "abuseipdb": {"status": "clean"},
        })
        self.assertEqual(verdict["assessment"], "no_suspicious_findings")
        self.assertEqual(sorted(verdict["clean"]), ["abuseipdb", "virustotal"])
        self._assert_no_confidence(verdict)

    def test_insufficient_data(self) -> None:
        verdict = compute_verdict({
            "virustotal": {"status": "n/a"},
            "otx": {"status": "error"},
        })
        self.assertEqual(verdict["assessment"], "insufficient_data")
        self.assertEqual(verdict["responding"], [])
        self._assert_no_confidence(verdict)
        self._assert_no_confidence(compute_verdict({}))

    def test_reasoning_lists_each_responding_provider(self) -> None:
        verdict = compute_verdict({
            "virustotal": {
                "status": "malicious",
                "details": {"malicious": 4, "suspicious": 0, "harmless": 60, "undetected": 6, "vendor_total": 70},
            },
            "otx": {"status": "clean"},
            "threatfox": {"status": "n/a"},
        })
        self.assertIn("virustotal: malicious (4/70 vendors)", verdict["reasoning"])
        self.assertIn("otx: clean", verdict["reasoning"])
        self.assertNotIn("threatfox", verdict["reasoning"])


class PrivateIndicatorNeverLeavesTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_scan_cache()

    def tearDown(self) -> None:
        clear_scan_cache()

    def _scan(self, value: str) -> dict:
        with patch("src.ioc_enrichment.requests.get", side_effect=AssertionError("HTTP GET must not run")), \
             patch("src.ioc_enrichment.requests.post", side_effect=AssertionError("HTTP POST must not run")), \
             patch("src.ioc_enrichment._http_get_json", side_effect=AssertionError("HTTP must not run")), \
             patch("src.ioc_enrichment._http_post_json", side_effect=AssertionError("HTTP must not run")):
            return scan_ioc(
                value,
                providers={"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True},
                api_keys={"virustotal": "k", "abuseipdb": "k", "otx": "k", "threatfox": "k"},
            )

    def test_rfc1918_10_range_is_skipped(self) -> None:
        result = self._scan("10.0.0.5")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "private_or_reserved_ip")
        self.assertEqual(result["providers"], {})
        self.assertEqual(result["verdict"]["assessment"], "insufficient_data")

    def test_rfc1918_192_range_is_skipped(self) -> None:
        result = self._scan("192.168.1.1")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "private_or_reserved_ip")

    def test_corp_domain_is_skipped(self) -> None:
        result = self._scan("fileserver.corp")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "non_public_domain")

    def test_intranet_url_is_skipped(self) -> None:
        result = self._scan("http://intranet.local/x")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "non_public_domain")

    def test_skipped_scan_is_not_cached(self) -> None:
        from src.ioc_enrichment import _SCAN_CACHE

        self._scan("10.0.0.5")
        self.assertEqual(len(_SCAN_CACHE), 0)

    def test_is_scannable_ioc_rules(self) -> None:
        self.assertEqual(is_scannable_ioc("8.8.8.8", "ip"), (True, ""))
        self.assertEqual(is_scannable_ioc("127.0.0.1", "ip"), (False, "private_or_reserved_ip"))
        self.assertEqual(is_scannable_ioc("169.254.1.1", "ip"), (False, "private_or_reserved_ip"))
        self.assertEqual(is_scannable_ioc("example.com", "domain"), (True, ""))
        self.assertEqual(is_scannable_ioc("localhost", "domain"), (False, "non_public_domain"))
        self.assertEqual(is_scannable_ioc("host.example", "domain"), (False, "non_public_domain"))
        self.assertEqual(is_scannable_ioc("https://example.com/a", "url"), (True, ""))
        self.assertEqual(is_scannable_ioc("http://10.0.0.5/a", "url"), (False, "private_or_reserved_ip"))
        self.assertEqual(is_scannable_ioc("a" * 64, "hash"), (True, ""))


class EpcPlanNeverOpensWithIsolationTests(unittest.TestCase):
    def test_t1059_plan_does_not_start_with_isolate(self) -> None:
        epc = _build_epc(_mapping("T1059"), {"process": "powershell.exe"})
        self.assertNotIn("Isolate", epc.plan[0])
        self.assertIn("Decode", epc.plan[0])
        self.assertEqual(len(epc.plan), 3)

    def test_t1055_plan_does_not_start_with_isolate(self) -> None:
        mapping = AttackMapping(
            technique_id="T1055",
            technique_name="Process Injection",
            evidence_strength="strong",
            rationale="test",
            evidence_refs=["createremotethread"],
        )
        epc = _build_epc(mapping, {"process": "lsass.exe"})
        self.assertNotIn("Isolate", epc.plan[0])
        self.assertIn("Confirm the process access target", epc.plan[0])

    def test_no_epc_plan_opens_with_isolation(self) -> None:
        for technique_id in ("T1059", "T1071", "T1110", "T1053", "T1003", "T1070", "T1021", "T1055", "T1999"):
            with self.subTest(technique=technique_id):
                mapping = AttackMapping(
                    technique_id=technique_id,
                    technique_name="x",
                    evidence_strength="moderate",
                    rationale="test",
                    evidence_refs=["e"],
                )
                epc = _build_epc(mapping, {})
                self.assertFalse(epc.plan[0].lower().startswith("isolate"))


if __name__ == "__main__":
    unittest.main()
