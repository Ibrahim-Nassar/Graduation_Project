from __future__ import annotations

import unittest
from unittest.mock import patch

import requests

from src.ioc_enrichment import (
    IOC_TYPE_DOMAIN,
    IOC_TYPE_HASH,
    IOC_TYPE_IP,
    IOC_TYPE_URL,
    IOC_TYPE_UNKNOWN,
    _aggregate_status,
    _classify_http_error,
    abuseipdb_lookup,
    compute_verdict,
    detect_ioc_type,
    otx_lookup,
    threatfox_lookup,
    vt_lookup,
)


class DetectIocTypeTests(unittest.TestCase):
    def test_detects_valid_ipv4(self) -> None:
        self.assertEqual(detect_ioc_type("8.8.8.8"), IOC_TYPE_IP)

    def test_detects_valid_domain(self) -> None:
        self.assertEqual(detect_ioc_type("example.com"), IOC_TYPE_DOMAIN)

    def test_detects_valid_url(self) -> None:
        self.assertEqual(detect_ioc_type("https://example.com/path?q=1"), IOC_TYPE_URL)

    def test_detects_valid_hash_lengths(self) -> None:
        self.assertEqual(detect_ioc_type("a" * 32), IOC_TYPE_HASH)
        self.assertEqual(detect_ioc_type("b" * 64), IOC_TYPE_HASH)

    def test_invalid_and_edge_inputs_return_unknown(self) -> None:
        self.assertEqual(detect_ioc_type(""), IOC_TYPE_UNKNOWN)
        self.assertEqual(detect_ioc_type("999.999.999.999"), IOC_TYPE_UNKNOWN)
        self.assertEqual(detect_ioc_type("not-an-ioc"), IOC_TYPE_UNKNOWN)


class ProviderLookupHandlingTests(unittest.TestCase):
    def test_vt_missing_api_key_returns_na_without_crash(self) -> None:
        result = vt_lookup("8.8.8.8", IOC_TYPE_IP, "")
        self.assertEqual(result["status"], "n/a")
        self.assertIn("missing API key", result.get("error", ""))

    def test_vt_three_or_more_malicious_vendors_maps_to_malicious(self) -> None:
        payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 0, "harmless": 0}}}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = vt_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "malicious")
        self.assertEqual(result["details"]["vendor_total"], 3)

    def test_vt_one_or_two_malicious_vendors_maps_to_suspicious(self) -> None:
        payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 0}}}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = vt_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "suspicious")
        self.assertEqual(result["details"]["vendor_total"], 2)

    def test_vt_empty_payload_maps_to_unknown(self) -> None:
        with patch("src.ioc_enrichment._http_get_json", return_value={}):
            result = vt_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(int(result["score"]), 0)

    def test_vt_nested_malformed_but_safe_payload_maps_to_unknown(self) -> None:
        payload = {"data": {"attributes": {}}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = vt_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(int(result["score"]), 0)

    def test_vt_http_error_sets_error_field(self) -> None:
        response = requests.Response()
        response.status_code = 429
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_get_json", side_effect=http_error):
            result = vt_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "error")
        self.assertIn("error", result)

    def test_abuseipdb_success_maps_to_clean_or_suspicious_or_malicious(self) -> None:
        payload = {"data": {"abuseConfidenceScore": 80, "totalReports": 12}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = abuseipdb_lookup("8.8.8.8", "k")
        self.assertEqual(result["status"], "malicious")
        self.assertEqual(int(result["score"]), 80)

    def test_abuseipdb_missing_api_key_returns_na_without_crash(self) -> None:
        result = abuseipdb_lookup("8.8.8.8", "")
        self.assertEqual(result["status"], "n/a")
        self.assertIn("missing API key", result.get("error", ""))

    def test_abuseipdb_empty_payload_maps_to_clean(self) -> None:
        with patch("src.ioc_enrichment._http_get_json", return_value={}):
            result = abuseipdb_lookup("8.8.8.8", "k")
        self.assertEqual(result["status"], "clean")
        self.assertEqual(int(result["score"]), 0)

    def test_abuseipdb_nested_malformed_but_safe_payload_maps_to_clean(self) -> None:
        payload = {"data": {"abuseConfidenceScore": None, "totalReports": None}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = abuseipdb_lookup("8.8.8.8", "k")
        self.assertEqual(result["status"], "clean")
        self.assertEqual(int(result["score"]), 0)

    def test_abuseipdb_http_error_sets_error_field(self) -> None:
        response = requests.Response()
        response.status_code = 500
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_get_json", side_effect=http_error):
            result = abuseipdb_lookup("8.8.8.8", "k")
        self.assertEqual(result["status"], "error")
        self.assertIn("error", result)

    def test_otx_success_maps_to_suspicious_or_malicious(self) -> None:
        payload = {"pulse_info": {"count": 3}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = otx_lookup("example.com", IOC_TYPE_DOMAIN, "k")
        self.assertEqual(result["status"], "suspicious")
        self.assertGreater(int(result["score"]), 0)

    def test_otx_missing_api_key_returns_na_without_crash(self) -> None:
        result = otx_lookup("example.com", IOC_TYPE_DOMAIN, "")
        self.assertEqual(result["status"], "n/a")
        self.assertIn("missing API key", result.get("error", ""))

    def test_otx_empty_payload_maps_to_clean(self) -> None:
        with patch("src.ioc_enrichment._http_get_json", return_value={}):
            result = otx_lookup("example.com", IOC_TYPE_DOMAIN, "k")
        self.assertEqual(result["status"], "clean")
        self.assertEqual(int(result["score"]), 10)

    def test_otx_nested_malformed_but_safe_payload_maps_to_clean(self) -> None:
        with patch("src.ioc_enrichment._http_get_json", return_value={"pulse_info": None}):
            result = otx_lookup("example.com", IOC_TYPE_DOMAIN, "k")
        self.assertEqual(result["status"], "clean")
        self.assertEqual(int(result["score"]), 10)

    def test_otx_http_error_sets_error_field(self) -> None:
        response = requests.Response()
        response.status_code = 500
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_get_json", side_effect=http_error):
            result = otx_lookup("example.com", IOC_TYPE_DOMAIN, "k")
        self.assertEqual(result["status"], "error")
        self.assertIn("http 500", result["error"])

    def test_otx_auth_error_on_401(self) -> None:
        response = requests.Response()
        response.status_code = 401
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_get_json", side_effect=http_error):
            result = otx_lookup("example.com", IOC_TYPE_DOMAIN, "k")
        self.assertEqual(result["status"], "auth_error")
        self.assertIn("invalid or expired API key", result["error"])
        self.assertIn("otx", result["error"])

    def test_threatfox_success_maps_to_malicious(self) -> None:
        payload = {
            "query_status": "ok",
            "data": [{"confidence_level": 90}],
        }
        with patch("src.ioc_enrichment._http_post_json", return_value=payload):
            result = threatfox_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "malicious")
        self.assertEqual(int(result["score"]), 90)

    def test_threatfox_missing_api_key_returns_na_without_crash(self) -> None:
        result = threatfox_lookup("8.8.8.8", IOC_TYPE_IP, "")
        self.assertEqual(result["status"], "n/a")
        self.assertIn("missing API key", result.get("error", ""))

    def test_threatfox_empty_response_maps_to_not_found(self) -> None:
        with patch("src.ioc_enrichment._http_post_json", return_value={"query_status": "no_result"}):
            result = threatfox_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "not_found")
        self.assertEqual(int(result["score"]), 0)

    def test_threatfox_malformed_response_is_handled_safely(self) -> None:
        with patch("src.ioc_enrichment._http_post_json", return_value={"message": "weird"}):
            result = threatfox_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertIn(result["status"], {"not_found", "error"})

    def test_threatfox_nested_malformed_but_safe_payload_maps_to_suspicious(self) -> None:
        payload = {
            "query_status": "ok",
            "data": [{"confidence_level": 15}, {}],
        }
        with patch("src.ioc_enrichment._http_post_json", return_value=payload):
            result = threatfox_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "suspicious")

    def test_threatfox_http_error_sets_error_field(self) -> None:
        response = requests.Response()
        response.status_code = 500
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_post_json", side_effect=http_error):
            result = threatfox_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "error")
        self.assertIn("http 500", result["error"])

    def test_threatfox_auth_error_on_403(self) -> None:
        response = requests.Response()
        response.status_code = 403
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_post_json", side_effect=http_error):
            result = threatfox_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "auth_error")
        self.assertIn("invalid or expired API key", result["error"])
        self.assertIn("threatfox", result["error"])


class AggregationLogicTests(unittest.TestCase):
    def test_aggregate_status_all_clean(self) -> None:
        result = _aggregate_status(
            {
                "virustotal": {"status": "clean"},
                "otx": {"status": "clean"},
            }
        )
        self.assertEqual(result, "clean")

    def test_aggregate_status_mixed_clean_and_malicious(self) -> None:
        result = _aggregate_status(
            {
                "virustotal": {"status": "clean"},
                "otx": {"status": "malicious"},
            }
        )
        self.assertEqual(result, "malicious")

    def test_aggregate_status_unknown_only(self) -> None:
        result = _aggregate_status(
            {
                "virustotal": {"status": "unknown"},
                "otx": {"status": "n/a"},
            }
        )
        self.assertEqual(result, "unknown")

    def test_aggregate_status_error_handled_as_unknown(self) -> None:
        result = _aggregate_status(
            {
                "virustotal": {"status": "error"},
                "otx": {"status": "n/a"},
            }
        )
        self.assertEqual(result, "unknown")


class VerdictComputationTests(unittest.TestCase):
    def test_all_malicious_returns_corroborated_malicious(self) -> None:
        results = {
            "virustotal": {"status": "malicious"},
            "otx": {"status": "malicious"},
            "threatfox": {"status": "malicious"},
        }
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "corroborated_malicious")
        self.assertIn("malicious", verdict["reasoning"].lower())
        self.assertEqual(sorted(verdict["responding"]), ["otx", "threatfox", "virustotal"])

    def test_all_clean_returns_no_suspicious_findings(self) -> None:
        results = {
            "virustotal": {"status": "clean"},
            "otx": {"status": "clean"},
            "abuseipdb": {"status": "clean"},
        }
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "no_suspicious_findings")
        self.assertEqual(sorted(verdict["clean"]), ["abuseipdb", "otx", "virustotal"])

    def test_suspicious_with_clean_is_providers_disagree(self) -> None:
        results = {
            "virustotal": {"status": "clean"},
            "otx": {"status": "suspicious"},
        }
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "providers_disagree")

    def test_single_malicious_with_clean_is_providers_disagree_not_malicious(self) -> None:
        results = {
            "virustotal": {"status": "malicious"},
            "otx": {"status": "clean"},
            "threatfox": {"status": "clean"},
        }
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "providers_disagree")
        self.assertEqual(verdict["malicious"], ["virustotal"])

    def test_empty_results_returns_insufficient_data(self) -> None:
        verdict = compute_verdict({})
        self.assertEqual(verdict["assessment"], "insufficient_data")
        self.assertEqual(verdict["responding"], [])

    def test_all_error_returns_insufficient_data(self) -> None:
        results = {
            "virustotal": {"status": "error"},
            "otx": {"status": "n/a"},
        }
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "insufficient_data")

    def test_verdict_keys_present_and_no_confidence(self) -> None:
        verdict = compute_verdict({"virustotal": {"status": "clean"}})
        for key in ("assessment", "reasoning", "responding", "malicious", "suspicious", "clean"):
            self.assertIn(key, verdict)
        self.assertNotIn("verdict", verdict)
        self.assertNotIn("confidence", verdict)

    def test_all_auth_error_returns_insufficient_data(self) -> None:
        results = {
            "virustotal": {"status": "auth_error"},
            "otx": {"status": "auth_error"},
        }
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "insufficient_data")

    def test_auth_error_mixed_with_clean_returns_no_suspicious_findings(self) -> None:
        results = {
            "virustotal": {"status": "auth_error"},
            "otx": {"status": "clean"},
        }
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "no_suspicious_findings")
        self.assertEqual(verdict["responding"], ["otx"])

    def test_reasoning_includes_virustotal_vendor_ratio(self) -> None:
        results = {
            "virustotal": {
                "status": "malicious",
                "details": {"malicious": 5, "suspicious": 0, "harmless": 60, "undetected": 5, "vendor_total": 70},
            },
        }
        verdict = compute_verdict(results)
        self.assertIn("5/70", verdict["reasoning"])


class AuthErrorClassificationTests(unittest.TestCase):
    def test_401_classified_as_auth_error(self) -> None:
        response = requests.Response()
        response.status_code = 401
        exc = requests.HTTPError(response=response)
        result = _classify_http_error(exc, "virustotal")
        self.assertEqual(result["status"], "auth_error")
        self.assertIn("invalid or expired API key", result["error"])
        self.assertIn("virustotal", result["error"])
        self.assertIn("401", result["error"])

    def test_403_classified_as_auth_error(self) -> None:
        response = requests.Response()
        response.status_code = 403
        exc = requests.HTTPError(response=response)
        result = _classify_http_error(exc, "abuseipdb")
        self.assertEqual(result["status"], "auth_error")
        self.assertIn("invalid or expired API key", result["error"])
        self.assertIn("abuseipdb", result["error"])
        self.assertIn("403", result["error"])

    def test_429_classified_as_generic_error(self) -> None:
        response = requests.Response()
        response.status_code = 429
        exc = requests.HTTPError(response=response)
        result = _classify_http_error(exc, "otx")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "http 429")

    def test_500_classified_as_generic_error(self) -> None:
        response = requests.Response()
        response.status_code = 500
        exc = requests.HTTPError(response=response)
        result = _classify_http_error(exc, "threatfox")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "http 500")

    def test_no_response_object_classified_as_generic_error(self) -> None:
        exc = requests.HTTPError(response=None)
        result = _classify_http_error(exc, "virustotal")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "http_error")

    def test_vt_401_returns_auth_error(self) -> None:
        response = requests.Response()
        response.status_code = 401
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_get_json", side_effect=http_error):
            result = vt_lookup("8.8.8.8", IOC_TYPE_IP, "bad_key")
        self.assertEqual(result["status"], "auth_error")
        self.assertIn("invalid or expired API key", result["error"])

    def test_abuseipdb_403_returns_auth_error(self) -> None:
        response = requests.Response()
        response.status_code = 403
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_get_json", side_effect=http_error):
            result = abuseipdb_lookup("8.8.8.8", "bad_key")
        self.assertEqual(result["status"], "auth_error")
        self.assertIn("invalid or expired API key", result["error"])


class AggregateStatusAuthErrorTests(unittest.TestCase):
    def test_all_auth_error_returns_auth_error(self) -> None:
        result = _aggregate_status({
            "virustotal": {"status": "auth_error"},
            "otx": {"status": "auth_error"},
        })
        self.assertEqual(result, "auth_error")

    def test_auth_error_mixed_with_clean_returns_clean(self) -> None:
        result = _aggregate_status({
            "virustotal": {"status": "auth_error"},
            "otx": {"status": "clean"},
        })
        self.assertEqual(result, "clean")

    def test_auth_error_mixed_with_na_returns_unknown(self) -> None:
        result = _aggregate_status({
            "virustotal": {"status": "auth_error"},
            "otx": {"status": "n/a"},
        })
        self.assertEqual(result, "unknown")

    def test_auth_error_mixed_with_malicious_returns_malicious(self) -> None:
        result = _aggregate_status({
            "virustotal": {"status": "auth_error"},
            "otx": {"status": "malicious"},
        })
        self.assertEqual(result, "malicious")


if __name__ == "__main__":
    unittest.main()
