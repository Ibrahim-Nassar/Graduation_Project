from __future__ import annotations

import base64
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import ioc_enrichment as ie


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            error = ie.requests.HTTPError(f"{self.status_code} Error")
            error.response = self
            raise error

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeInvalidJsonResponse(_FakeResponse):
    def json(self) -> dict[str, Any]:
        raise ValueError("invalid json")


def test_detect_ioc_type_supported_values() -> None:
    assert ie.detect_ioc_type("8.8.8.8") == "ip"
    assert ie.detect_ioc_type("2001:4860:4860::8888") == "ip"
    assert ie.detect_ioc_type("example.com") == "domain"
    assert ie.detect_ioc_type("https://example.com/login") == "url"
    assert ie.detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"


def test_is_valid_and_parse_ioc() -> None:
    assert ie.is_valid_ioc("example.com") is True
    assert ie.is_valid_ioc("not an ioc") is False
    assert ie.parse_ioc("Example.COM") == {
        "type": "domain",
        "value": "Example.COM",
        "normalized": "example.com",
    }
    assert ie.parse_ioc("not an ioc") is None


def test_invalid_ioc_returns_expected_shape() -> None:
    result = ie.scan_ioc("definitely not valid")

    assert result == {
        "ioc": "definitely not valid",
        "type": "unknown",
        "status": "invalid",
        "score": 0,
        "providers": {},
        "errors": ["Invalid IOC"],
    }


def test_abuseipdb_skipped_for_non_ip() -> None:
    result = ie.scan_ioc(
        "example.com",
        providers={
            "virustotal": False,
            "abuseipdb": True,
            "otx": False,
            "threatfox": False,
        },
        api_keys={"abuseipdb": "key"},
    )

    assert result["type"] == "domain"
    assert result["providers"] == {}
    assert "abuseipdb" not in result["providers"]


def test_missing_api_key_returns_provider_error() -> None:
    result = ie.scan_ioc(
        "8.8.8.8",
        providers={
            "virustotal": True,
            "abuseipdb": False,
            "otx": False,
            "threatfox": False,
        },
        api_keys={},
    )

    provider_result = result["providers"]["virustotal"]
    assert provider_result["provider"] == "virustotal"
    assert provider_result["status"] == "error"
    assert provider_result["score"] == 0
    assert provider_result["details"] == {}
    assert provider_result["error"] == "Missing VirusTotal API key"


def test_scan_ioc_returns_deterministic_aggregation_shape(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        url = args[0]
        if "virustotal.com" in url:
            return _FakeResponse(
                {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 0,
                                "harmless": 0,
                                "undetected": 0,
                            },
                            "country": None,
                            "asn": None,
                            "as_owner": None,
                        }
                    }
                }
            )
        return _FakeResponse(
            {
                "data": {
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                    "countryCode": None,
                    "isp": None,
                    "domain": None,
                    "lastReportedAt": None,
                }
            }
        )

    monkeypatch.setattr(ie.requests, "get", fake_get)
    monkeypatch.setattr(ie.requests, "post", lambda *args, **kwargs: _FakeResponse({"query_status": "no_result"}))
    result = ie.scan_ioc(
        "8.8.8.8",
        providers={
            "virustotal": True,
            "abuseipdb": True,
            "otx": True,
            "threatfox": True,
        },
        api_keys={
            "virustotal": "vt_key",
            "abuseipdb": "abuse_key",
            "otx": "otx_key",
            "threatfox": "tf_key",
        },
    )

    assert result == {
        "ioc": "8.8.8.8",
        "type": "ip",
        "status": "unknown",
        "score": 0,
        "providers": {
            "virustotal": {
                "provider": "virustotal",
                "ioc": "8.8.8.8",
                "type": "ip",
                "status": "unknown",
                "score": 0,
                "details": {
                    "stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0,
                    },
                    "enginesTotal": 0,
                    "maliciousCount": 0,
                    "meta": {"country": None, "asn": None, "asnOwner": None},
                },
            },
            "abuseipdb": {
                "provider": "abuseipdb",
                "ioc": "8.8.8.8",
                "type": "ip",
                "status": "unknown",
                "score": 0,
                "details": {
                    "confidence": 0,
                    "reports": 0,
                    "countryCode": None,
                    "isp": None,
                    "domain": None,
                    "lastReportedAt": None,
                },
            },
            "otx": {
                "provider": "otx",
                "ioc": "8.8.8.8",
                "type": "ip",
                "status": "unknown",
                "score": 0,
                "details": {
                    "pulses": 0,
                    "reputation": 0,
                },
            },
            "threatfox": {
                "provider": "threatfox",
                "ioc": "8.8.8.8",
                "type": "ip",
                "status": "unknown",
                "score": 0,
                "details": {"count": 0},
            },
        },
    }


def test_abuseipdb_success_path_parses_response(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        assert kwargs["headers"]["Key"] == "abuse_key"
        assert kwargs["params"] == {"ipAddress": "8.8.8.8", "maxAgeInDays": 365}
        assert kwargs["timeout"] == 15
        return _FakeResponse(
            {
                "data": {
                    "abuseConfidenceScore": 88,
                    "totalReports": 42,
                    "countryCode": "US",
                    "isp": "Google",
                    "domain": "google.com",
                    "lastReportedAt": "2026-03-10T00:00:00+00:00",
                }
            }
        )

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.abuseipdb_lookup("8.8.8.8", api_key="abuse_key")

    assert result["provider"] == "abuseipdb"
    assert result["status"] == "malicious"
    assert result["score"] == 88
    assert result["details"] == {
        "confidence": 88,
        "reports": 42,
        "countryCode": "US",
        "isp": "Google",
        "domain": "google.com",
        "lastReportedAt": "2026-03-10T00:00:00+00:00",
    }


def test_abuseipdb_uses_environment_api_key(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        assert kwargs["headers"]["Key"] == "env_key"
        return _FakeResponse({"data": {"abuseConfidenceScore": 25}})

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "env_key")
    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.abuseipdb_lookup("1.1.1.1", api_key=None)

    assert result["status"] == "suspicious"
    assert result["score"] == 25


def test_abuseipdb_unsupported_input_returns_neutral_result() -> None:
    result = ie.abuseipdb_lookup("example.com", api_key="abuse_key")
    assert result == {
        "provider": "abuseipdb",
        "status": "unknown",
        "score": 0,
        "details": {
            "skipped": True,
            "reason": "unsupported_ioc_type",
            "supported_types": ["ip"],
        },
    }


def test_abuseipdb_http_error_returns_provider_error(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        raise ie.requests.RequestException("timeout")

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.abuseipdb_lookup("8.8.8.8", api_key="abuse_key")

    assert result["provider"] == "abuseipdb"
    assert result["status"] == "error"
    assert result["score"] == 0
    assert result["details"] == {}
    assert "AbuseIPDB API error: timeout" == result["error"]


def test_abuseipdb_malformed_response_defaults_safely(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"unexpected": "shape"})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.abuseipdb_lookup("8.8.8.8", api_key="abuse_key")

    assert result["provider"] == "abuseipdb"
    assert result["status"] == "unknown"
    assert result["score"] == 0
    assert result["details"] == {
        "confidence": 0,
        "reports": 0,
        "countryCode": None,
        "isp": None,
        "domain": None,
        "lastReportedAt": None,
    }


def test_abuseipdb_invalid_json_response_returns_error(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeInvalidJsonResponse:
        return _FakeInvalidJsonResponse({})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.abuseipdb_lookup("8.8.8.8", api_key="abuse_key")

    assert result["provider"] == "abuseipdb"
    assert result["status"] == "error"
    assert result["score"] == 0
    assert result["details"] == {}
    assert result["error"] == "AbuseIPDB API error: Invalid JSON response"


def test_virustotal_supported_types_use_expected_endpoints(monkeypatch) -> None:
    seen_urls: list[str] = []

    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        seen_urls.append(args[0])
        return _FakeResponse(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 1,
                            "undetected": 1,
                        }
                    }
                }
            }
        )

    monkeypatch.setattr(ie.requests, "get", fake_get)

    ie.vt_lookup("8.8.8.8", "ip", api_key="vt_key")
    ie.vt_lookup("example.com", "domain", api_key="vt_key")
    ie.vt_lookup("d41d8cd98f00b204e9800998ecf8427e", "hash", api_key="vt_key")
    ie.vt_lookup("https://example.com/login", "url", api_key="vt_key")

    url_id = base64.b64encode("https://example.com/login".encode("utf-8")).decode("ascii").rstrip("=")
    assert seen_urls[0].endswith("/ip_addresses/8.8.8.8")
    assert seen_urls[1].endswith("/domains/example.com")
    assert seen_urls[2].endswith("/files/d41d8cd98f00b204e9800998ecf8427e")
    assert seen_urls[3].endswith(f"/urls/{url_id}")


def test_virustotal_success_path_parses_response(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        assert kwargs["headers"]["x-apikey"] == "vt_key"
        assert kwargs["timeout"] == 20
        return _FakeResponse(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 5,
                            "undetected": 2,
                        },
                        "country": "US",
                        "asn": 15169,
                        "as_owner": "GOOGLE LLC",
                    }
                }
            }
        )

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.vt_lookup("8.8.8.8", "ip", api_key="vt_key")

    assert result["provider"] == "virustotal"
    assert result["status"] == "malicious"
    assert result["score"] == 20
    assert result["details"] == {
        "stats": {"malicious": 2, "suspicious": 1, "harmless": 5, "undetected": 2},
        "enginesTotal": 10,
        "maliciousCount": 2,
        "meta": {"country": "US", "asn": 15169, "asnOwner": "GOOGLE LLC"},
    }


def test_virustotal_unsupported_type_returns_neutral_result() -> None:
    result = ie.vt_lookup("anything", "email", api_key="vt_key")
    assert result == {
        "provider": "virustotal",
        "status": "unknown",
        "score": 0,
        "details": {
            "skipped": True,
            "reason": "unsupported_ioc_type",
            "supported_types": ["ip", "domain", "hash", "url"],
        },
    }


def test_virustotal_uses_environment_api_key(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        assert kwargs["headers"]["x-apikey"] == "env_vt_key"
        return _FakeResponse({"data": {"attributes": {"last_analysis_stats": {}}}})

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env_vt_key")
    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.vt_lookup("example.com", "domain", api_key=None)

    assert result["provider"] == "virustotal"
    assert result["status"] == "unknown"
    assert result["score"] == 0


def test_virustotal_http_error_returns_provider_error(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        raise ie.requests.RequestException("connection reset")

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.vt_lookup("example.com", "domain", api_key="vt_key")

    assert result["provider"] == "virustotal"
    assert result["status"] == "error"
    assert result["score"] == 0
    assert result["details"] == {}
    assert result["error"] == "VirusTotal API error: connection reset"


def test_virustotal_invalid_json_response_returns_error(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeInvalidJsonResponse:
        return _FakeInvalidJsonResponse({})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.vt_lookup("example.com", "domain", api_key="vt_key")

    assert result["provider"] == "virustotal"
    assert result["status"] == "error"
    assert result["score"] == 0
    assert result["details"] == {}
    assert result["error"] == "VirusTotal API error: Invalid JSON response"


def test_virustotal_malformed_response_defaults_safely(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"unexpected": "shape"})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.vt_lookup("example.com", "domain", api_key="vt_key")

    assert result["provider"] == "virustotal"
    assert result["status"] == "unknown"
    assert result["score"] == 0
    assert result["details"] == {"stats": {}, "enginesTotal": 0, "maliciousCount": 0}


def test_virustotal_scan_aggregation_compatibility_is_deterministic(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 1,
                            "harmless": 6,
                            "undetected": 0,
                        }
                    }
                }
            }
        )

    monkeypatch.setattr(ie.requests, "get", fake_get)
    providers = {
        "virustotal": True,
        "abuseipdb": False,
        "otx": False,
        "threatfox": False,
    }
    api_keys = {"virustotal": "vt_key"}

    first = ie.scan_ioc("8.8.8.8", providers=providers, api_keys=api_keys)
    second = ie.scan_ioc("8.8.8.8", providers=providers, api_keys=api_keys)

    assert first == second
    assert first["status"] == "malicious"
    assert first["score"] == 30
    assert first["providers"]["virustotal"]["details"]["enginesTotal"] == 10


def test_otx_supported_types_use_expected_endpoints(monkeypatch) -> None:
    seen_urls: list[str] = []

    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        seen_urls.append(args[0])
        return _FakeResponse({"pulse_info": {"count": 0}, "reputation": 0})

    monkeypatch.setattr(ie.requests, "get", fake_get)

    ie.otx_lookup("8.8.8.8", "ip", api_key="otx_key")
    ie.otx_lookup("example.com", "domain", api_key="otx_key")
    ie.otx_lookup("d41d8cd98f00b204e9800998ecf8427e", "hash", api_key="otx_key")
    ie.otx_lookup("https://sub.example.com/login", "url", api_key="otx_key")

    assert seen_urls[0].endswith("/api/v1/indicators/IPv4/8.8.8.8/general")
    assert seen_urls[1].endswith("/api/v1/indicators/domain/example.com/general")
    assert seen_urls[2].endswith("/api/v1/indicators/file/d41d8cd98f00b204e9800998ecf8427e/general")
    assert seen_urls[3].endswith("/api/v1/indicators/domain/sub.example.com/general")


def test_otx_success_path_parses_response(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        assert kwargs["headers"]["X-OTX-API-KEY"] == "otx_key"
        assert kwargs["timeout"] == 20
        return _FakeResponse({"pulse_info": {"count": 8}, "reputation": -2})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.otx_lookup("8.8.8.8", "ip", api_key="otx_key")

    assert result["provider"] == "otx"
    assert result["status"] == "suspicious"
    assert result["score"] == 60
    assert result["details"] == {"pulses": 8, "reputation": -2}


def test_otx_unsupported_type_returns_neutral_result() -> None:
    result = ie.otx_lookup("anything", "email", api_key="otx_key")
    assert result == {
        "provider": "otx",
        "status": "unknown",
        "score": 0,
        "details": {
            "skipped": True,
            "reason": "unsupported_ioc_type",
            "supported_types": ["ip", "domain", "hash", "url"],
        },
    }


def test_otx_uses_environment_api_key(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        assert kwargs["headers"]["X-OTX-API-KEY"] == "env_otx_key"
        return _FakeResponse({"pulse_info": {"count": 3}, "reputation": 0})

    monkeypatch.setenv("OTX_API_KEY", "env_otx_key")
    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.otx_lookup("example.com", "domain", api_key=None)

    assert result["provider"] == "otx"
    assert result["status"] == "suspicious"
    assert result["score"] == 35


def test_otx_http_404_returns_unknown_zero_with_details(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({}, status_code=404)

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.otx_lookup("example.com", "domain", api_key="otx_key")

    assert result == {
        "provider": "otx",
        "status": "unknown",
        "score": 0,
        "details": {"pulses": 0, "reputation": 0, "summary": "No OTX indicator match"},
    }


def test_otx_http_403_returns_provider_error(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({}, status_code=403)

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.otx_lookup("example.com", "domain", api_key="otx_key")

    assert result["provider"] == "otx"
    assert result["status"] == "error"
    assert result["score"] == 0
    assert result["details"] == {}
    assert result["error"] == "Invalid OTX API key or access denied"


def test_otx_http_429_returns_provider_error(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({}, status_code=429)

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.otx_lookup("example.com", "domain", api_key="otx_key")

    assert result["provider"] == "otx"
    assert result["status"] == "error"
    assert result["score"] == 0
    assert result["details"] == {}
    assert result["error"] == "OTX API rate limit exceeded"


def test_otx_request_error_returns_provider_error(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        raise ie.requests.RequestException("network down")

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.otx_lookup("example.com", "domain", api_key="otx_key")

    assert result["provider"] == "otx"
    assert result["status"] == "error"
    assert result["score"] == 0
    assert result["details"] == {}
    assert result["error"] == "OTX API error: network down"


def test_otx_invalid_json_response_returns_error(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeInvalidJsonResponse:
        return _FakeInvalidJsonResponse({})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.otx_lookup("example.com", "domain", api_key="otx_key")

    assert result["provider"] == "otx"
    assert result["status"] == "error"
    assert result["score"] == 0
    assert result["details"] == {}
    assert result["error"] == "OTX API error: Invalid JSON response"


def test_otx_malformed_response_defaults_safely(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"unexpected": "shape"})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    result = ie.otx_lookup("example.com", "domain", api_key="otx_key")

    assert result["provider"] == "otx"
    assert result["status"] == "unknown"
    assert result["score"] == 0
    assert result["details"] == {"pulses": 0, "reputation": 0}


def test_otx_scan_aggregation_compatibility_is_deterministic(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"pulse_info": {"count": 10}, "reputation": -6})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    providers = {
        "virustotal": False,
        "abuseipdb": False,
        "otx": True,
        "threatfox": False,
    }
    api_keys = {"otx": "otx_key"}

    first = ie.scan_ioc("example.com", providers=providers, api_keys=api_keys)
    second = ie.scan_ioc("example.com", providers=providers, api_keys=api_keys)

    assert first == second
    assert first["status"] == "malicious"
    assert first["score"] == 80
    assert first["providers"]["otx"]["details"] == {"pulses": 10, "reputation": -6}


def test_threatfox_supported_types_send_expected_payload(monkeypatch) -> None:
    sent_payloads: list[dict[str, Any]] = []

    def fake_post(*args: Any, **kwargs: Any) -> _FakeResponse:
        assert args[0] == "https://threatfox-api.abuse.ch/api/v1/"
        assert kwargs["headers"]["Auth-Key"] == "tf_key"
        assert kwargs["headers"]["Content-Type"] == "application/json"
        assert kwargs["timeout"] == 20
        sent_payloads.append(kwargs["json"])
        return _FakeResponse({"query_status": "no_result"})

    monkeypatch.setattr(ie.requests, "post", fake_post)

    ie.threatfox_lookup("8.8.8.8", "ip", api_key="tf_key")
    ie.threatfox_lookup("example.com", "domain", api_key="tf_key")
    ie.threatfox_lookup("https://example.com/login", "url", api_key="tf_key")
    ie.threatfox_lookup("d41d8cd98f00b204e9800998ecf8427e", "hash", api_key="tf_key")

    assert sent_payloads[0] == {"query": "search_ioc", "search_term": "8.8.8.8", "exact_match": False}
    assert sent_payloads[1] == {"query": "search_ioc", "search_term": "example.com", "exact_match": True}
    assert sent_payloads[2] == {
        "query": "search_ioc",
        "search_term": "https://example.com/login",
        "exact_match": True,
    }
    assert sent_payloads[3] == {
        "query": "search_ioc",
        "search_term": "d41d8cd98f00b204e9800998ecf8427e",
        "exact_match": True,
    }


def test_threatfox_success_path_parses_response(monkeypatch) -> None:
    def fake_post(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            {
                "query_status": "ok",
                "data": [
                    {
                        "ioc": "example.com",
                        "confidence_level": 90,
                        "malware": "ExampleMalware",
                        "threat_type": "botnet_cc",
                        "ioc_type_desc": "domain",
                        "tags": ["c2", "phishing"],
                        "first_seen": "2026-03-01 00:00:00 UTC",
                        "last_seen": "2026-03-05 00:00:00 UTC",
                        "reporter": "abuse.ch",
                        "reference": "https://example.test/report",
                    },
                    {"ioc": "example.com", "confidence_level": 70},
                ],
            }
        )

    monkeypatch.setattr(ie.requests, "post", fake_post)
    result = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")

    assert result["provider"] == "threatfox"
    assert result["status"] == "malicious"
    assert result["score"] == 80
    assert result["details"]["count"] == 2
    assert result["details"]["confidences"] == [90, 70]
    assert result["details"]["foundIOCs"] == ["example.com", "example.com"]
    assert result["details"]["malware"] == "ExampleMalware"
    assert result["details"]["threat_type"] == "botnet_cc"


def test_threatfox_ip_filters_relevant_entries(monkeypatch) -> None:
    def fake_post(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            {
                "query_status": "ok",
                "data": [
                    {"ioc": "8.8.8.8", "confidence_level": 80},
                    {"ioc": "8.8.8.8:443", "confidence_level": 60},
                    {"ioc": "1.1.1.1", "confidence_level": 99},
                ],
            }
        )

    monkeypatch.setattr(ie.requests, "post", fake_post)
    result = ie.threatfox_lookup("8.8.8.8", "ip", api_key="tf_key")

    assert result["status"] == "suspicious"
    assert result["score"] == 70
    assert result["details"]["count"] == 2
    assert result["details"]["foundIOCs"] == ["8.8.8.8", "8.8.8.8:443"]


def test_threatfox_unsupported_type_returns_neutral_result() -> None:
    result = ie.threatfox_lookup("anything", "email", api_key="tf_key")
    assert result == {
        "provider": "threatfox",
        "status": "unknown",
        "score": 0,
        "details": {
            "skipped": True,
            "reason": "unsupported_ioc_type",
            "supported_types": ["ip", "domain", "url", "hash"],
        },
    }


def test_threatfox_uses_environment_api_key(monkeypatch) -> None:
    def fake_post(*args: Any, **kwargs: Any) -> _FakeResponse:
        assert kwargs["headers"]["Auth-Key"] == "env_tf_key"
        return _FakeResponse({"query_status": "no_result"})

    monkeypatch.setenv("THREATFOX_API_KEY", "env_tf_key")
    monkeypatch.setattr(ie.requests, "post", fake_post)
    result = ie.threatfox_lookup("example.com", "domain", api_key=None)

    assert result == {
        "provider": "threatfox",
        "status": "unknown",
        "score": 0,
        "details": {"count": 0},
    }


def test_threatfox_empty_no_result_paths(monkeypatch) -> None:
    def fake_post_no_result(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"query_status": "no_result"})

    monkeypatch.setattr(ie.requests, "post", fake_post_no_result)
    no_result = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")
    assert no_result["details"] == {"count": 0}

    def fake_post_other_status(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"query_status": "unknown_status"})

    monkeypatch.setattr(ie.requests, "post", fake_post_other_status)
    other_status = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")
    assert other_status["details"] == {"query_status": "unknown_status"}

    def fake_post_ok_empty_data(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"query_status": "ok", "data": []})

    monkeypatch.setattr(ie.requests, "post", fake_post_ok_empty_data)
    ok_empty = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")
    assert ok_empty["details"] == {"count": 0}


def test_threatfox_http_error_handling(monkeypatch) -> None:
    def fake_post_403(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({}, status_code=403)

    monkeypatch.setattr(ie.requests, "post", fake_post_403)
    error_403 = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")
    assert error_403["error"] == "Invalid ThreatFox API key or access denied"

    def fake_post_429(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({}, status_code=429)

    monkeypatch.setattr(ie.requests, "post", fake_post_429)
    error_429 = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")
    assert error_429["error"] == "ThreatFox API rate limit exceeded"

    def fake_post_500(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({}, status_code=500)

    monkeypatch.setattr(ie.requests, "post", fake_post_500)
    error_500 = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")
    assert error_500["error"] == "ThreatFox service temporarily unavailable"

    def fake_post_request_exc(*args: Any, **kwargs: Any) -> _FakeResponse:
        raise ie.requests.RequestException("network down")

    monkeypatch.setattr(ie.requests, "post", fake_post_request_exc)
    request_error = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")
    assert request_error["error"] == "ThreatFox API error: network down"


def test_threatfox_invalid_json_response_returns_error(monkeypatch) -> None:
    def fake_post(*args: Any, **kwargs: Any) -> _FakeInvalidJsonResponse:
        return _FakeInvalidJsonResponse({})

    monkeypatch.setattr(ie.requests, "post", fake_post)
    result = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")

    assert result["provider"] == "threatfox"
    assert result["status"] == "error"
    assert result["score"] == 0
    assert result["details"] == {}
    assert result["error"] == "ThreatFox API error: Invalid JSON response"


def test_threatfox_malformed_response_defaults_safely(monkeypatch) -> None:
    def fake_post(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"unexpected": "shape"})

    monkeypatch.setattr(ie.requests, "post", fake_post)
    result = ie.threatfox_lookup("example.com", "domain", api_key="tf_key")

    assert result["provider"] == "threatfox"
    assert result["status"] == "unknown"
    assert result["score"] == 0
    assert result["details"] == {"query_status": None}


def test_threatfox_scan_aggregation_compatibility_is_deterministic(monkeypatch) -> None:
    def fake_post(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            {
                "query_status": "ok",
                "data": [
                    {"ioc": "example.com", "confidence_level": 95},
                    {"ioc": "example.com", "confidence_level": 85},
                ],
            }
        )

    monkeypatch.setattr(ie.requests, "post", fake_post)
    providers = {
        "virustotal": False,
        "abuseipdb": False,
        "otx": False,
        "threatfox": True,
    }
    api_keys = {"threatfox": "tf_key"}

    first = ie.scan_ioc("example.com", providers=providers, api_keys=api_keys)
    second = ie.scan_ioc("example.com", providers=providers, api_keys=api_keys)

    assert first == second
    assert first["status"] == "malicious"
    assert first["score"] == 90
    assert first["providers"]["threatfox"]["details"]["count"] == 2


def test_abuseipdb_scan_aggregation_compatibility_is_deterministic(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"data": {"abuseConfidenceScore": 30, "totalReports": 3}})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    providers = {
        "virustotal": False,
        "abuseipdb": True,
        "otx": False,
        "threatfox": False,
    }
    api_keys = {"abuseipdb": "abuse_key"}

    first = ie.scan_ioc("8.8.8.8", providers=providers, api_keys=api_keys)
    second = ie.scan_ioc("8.8.8.8", providers=providers, api_keys=api_keys)

    assert first == second
    assert first["status"] == "suspicious"
    assert first["score"] == 30
    assert first["providers"]["abuseipdb"]["details"]["reports"] == 3


def test_scan_ioc_provider_contract_core_keys_on_success(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        url = args[0]
        if "virustotal.com" in url:
            return _FakeResponse(
                {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 1,
                                "suspicious": 0,
                                "harmless": 1,
                                "undetected": 0,
                            }
                        }
                    }
                }
            )
        if "abuseipdb.com" in url:
            return _FakeResponse({"data": {"abuseConfidenceScore": 30}})
        return _FakeResponse({"pulse_info": {"count": 3}, "reputation": 0})

    def fake_post(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"query_status": "ok", "data": [{"ioc": "8.8.8.8", "confidence_level": 80}]})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    monkeypatch.setattr(ie.requests, "post", fake_post)
    result = ie.scan_ioc(
        "8.8.8.8",
        providers={"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True},
        api_keys={
            "virustotal": "vt_key",
            "abuseipdb": "abuse_key",
            "otx": "otx_key",
            "threatfox": "tf_key",
        },
    )

    core_keys = {"provider", "ioc", "type", "status", "score", "details"}
    for provider_name in ("virustotal", "abuseipdb", "otx", "threatfox"):
        provider_payload = result["providers"][provider_name]
        assert core_keys.issubset(provider_payload.keys())
        assert provider_payload["provider"] == provider_name
        assert provider_payload["ioc"] == "8.8.8.8"
        assert provider_payload["type"] == "ip"
        assert isinstance(provider_payload["details"], dict)


def test_scan_ioc_provider_contract_core_keys_on_error(monkeypatch) -> None:
    result = ie.scan_ioc(
        "8.8.8.8",
        providers={"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True},
        api_keys={},
    )

    core_keys = {"provider", "ioc", "type", "status", "score", "details", "error"}
    for provider_name in ("virustotal", "abuseipdb", "otx", "threatfox"):
        provider_payload = result["providers"][provider_name]
        assert core_keys.issubset(provider_payload.keys())
        assert provider_payload["status"] == "error"
        assert provider_payload["score"] == 0
        assert isinstance(provider_payload["error"], str)


def test_unsupported_ioc_handling_consistent_for_direct_provider_calls() -> None:
    vt = ie.vt_lookup("anything", "email", api_key="vt_key")
    otx = ie.otx_lookup("anything", "email", api_key="otx_key")
    tf = ie.threatfox_lookup("anything", "email", api_key="tf_key")

    for payload in (vt, otx, tf):
        assert payload["status"] == "unknown"
        assert payload["score"] == 0
        assert payload["details"]["skipped"] is True
        assert payload["details"]["reason"] == "unsupported_ioc_type"

    abuse = ie.abuseipdb_lookup("example.com", api_key="abuse_key")
    assert abuse["status"] == "unknown"
    assert abuse["score"] == 0
    assert abuse["details"]["skipped"] is True
    assert abuse["details"]["reason"] == "unsupported_ioc_type"


def test_scan_ioc_deterministic_aggregation_with_mixed_provider_outputs(monkeypatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        url = args[0]
        if "virustotal.com" in url:
            return _FakeResponse(
                {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 1,
                                "suspicious": 0,
                                "harmless": 9,
                                "undetected": 0,
                            }
                        }
                    }
                }
            )
        if "abuseipdb.com" in url:
            return _FakeResponse({"data": {"abuseConfidenceScore": 20}})
        return _FakeResponse({"pulse_info": {"count": 0}, "reputation": 0})

    def fake_post(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({"query_status": "ok", "data": [{"ioc": "8.8.8.8", "confidence_level": 40}]})

    monkeypatch.setattr(ie.requests, "get", fake_get)
    monkeypatch.setattr(ie.requests, "post", fake_post)
    providers = {"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True}
    api_keys = {"virustotal": "vt_key", "abuseipdb": "abuse_key", "otx": "otx_key", "threatfox": "tf_key"}

    first = ie.scan_ioc("8.8.8.8", providers=providers, api_keys=api_keys)
    second = ie.scan_ioc("8.8.8.8", providers=providers, api_keys=api_keys)

    assert first == second
    assert first["status"] == "malicious"
    assert first["score"] == 18
