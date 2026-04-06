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
    _aggregate_score,
    _aggregate_status,
    abuseipdb_lookup,
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

    def test_vt_success_maps_to_malicious(self) -> None:
        payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 0}}}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = vt_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "malicious")
        self.assertGreaterEqual(int(result["score"]), 80)

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
        response.status_code = 401
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_get_json", side_effect=http_error):
            result = otx_lookup("example.com", IOC_TYPE_DOMAIN, "k")
        self.assertEqual(result["status"], "error")
        self.assertIn("error", result)

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
        response.status_code = 403
        http_error = requests.HTTPError(response=response)
        with patch("src.ioc_enrichment._http_post_json", side_effect=http_error):
            result = threatfox_lookup("8.8.8.8", IOC_TYPE_IP, "k")
        self.assertEqual(result["status"], "error")
        self.assertIn("error", result)


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

    def test_aggregate_score_all_clean(self) -> None:
        score = _aggregate_score({"virustotal": {"status": "clean"}, "otx": {"status": "clean"}})
        self.assertEqual(score, 10)

    def test_aggregate_score_mixed_clean_and_malicious(self) -> None:
        score = _aggregate_score({"virustotal": {"status": "clean"}, "otx": {"status": "malicious"}})
        self.assertEqual(score, 50)

    def test_aggregate_score_unknown_only(self) -> None:
        score = _aggregate_score({"virustotal": {"status": "unknown"}})
        self.assertEqual(score, 0)

    def test_aggregate_score_error_is_handled(self) -> None:
        score = _aggregate_score({"virustotal": {"status": "error"}})
        self.assertEqual(score, 0)


if __name__ == "__main__":
    unittest.main()
