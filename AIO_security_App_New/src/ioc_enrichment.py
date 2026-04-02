from __future__ import annotations

import base64
import ipaddress
import os
import re
from typing import Any
from urllib.parse import quote, urlparse

import requests


IOC_TYPE_IP = "ip"
IOC_TYPE_DOMAIN = "domain"
IOC_TYPE_URL = "url"
IOC_TYPE_HASH = "hash"
IOC_TYPE_UNKNOWN = "unknown"

VALID_PROVIDER_STATUSES = {"malicious", "suspicious", "clean", "unknown", "error"}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$"
)
_HEX_RE = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)


def detect_ioc_type(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return IOC_TYPE_UNKNOWN

    try:
        ipaddress.ip_address(raw)
        return IOC_TYPE_IP
    except ValueError:
        pass

    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return IOC_TYPE_URL

    if _DOMAIN_RE.fullmatch(raw):
        return IOC_TYPE_DOMAIN

    if len(raw) in {32, 40, 64} and _HEX_RE.fullmatch(raw):
        return IOC_TYPE_HASH

    return IOC_TYPE_UNKNOWN


def is_valid_ioc(value: str) -> bool:
    return detect_ioc_type(value) != IOC_TYPE_UNKNOWN


def parse_ioc(value: str) -> dict[str, str] | None:
    ioc_type = detect_ioc_type(value)
    if ioc_type == IOC_TYPE_UNKNOWN:
        return None

    normalized = str(value).strip().lower()
    return {"type": ioc_type, "value": str(value).strip(), "normalized": normalized}


def make_provider_result(
    provider: str,
    status: str = "unknown",
    score: int = 0,
    details: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    normalized_status = status if status in VALID_PROVIDER_STATUSES else "error"
    result: dict[str, Any] = {
        "provider": provider,
        "status": normalized_status,
        "score": int(score),
        "details": details or {},
    }
    if error is not None:
        result["error"] = error
    return result


def vt_lookup(value: str, ioc_type: str, api_key: str | None = None) -> dict[str, Any]:
    resolved_api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
    if not resolved_api_key:
        return make_provider_result(
            "virustotal",
            status="error",
            score=0,
            details={},
            error="Missing VirusTotal API key",
        )

    raw_value = str(value or "")
    if ioc_type == IOC_TYPE_IP:
        endpoint = f"/ip_addresses/{quote(raw_value, safe='')}"
    elif ioc_type == IOC_TYPE_DOMAIN:
        endpoint = f"/domains/{quote(raw_value, safe='')}"
    elif ioc_type == IOC_TYPE_HASH:
        endpoint = f"/files/{quote(raw_value, safe='')}"
    elif ioc_type == IOC_TYPE_URL:
        url_id = base64.b64encode(raw_value.encode("utf-8")).decode("ascii").rstrip("=")
        endpoint = f"/urls/{url_id}"
    else:
        return make_provider_result(
            "virustotal",
            status="unknown",
            score=0,
            details={
                "skipped": True,
                "reason": "unsupported_ioc_type",
                "supported_types": ["ip", "domain", "hash", "url"],
            },
        )

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3{endpoint}",
            headers={"x-apikey": resolved_api_key},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        return make_provider_result(
            "virustotal",
            status="error",
            score=0,
            details={},
            error=f"VirusTotal API error: {exc}",
        )
    except ValueError:
        return make_provider_result(
            "virustotal",
            status="error",
            score=0,
            details={},
            error="VirusTotal API error: Invalid JSON response",
        )

    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}

    malicious = int(float(stats.get("malicious", 0) or 0)) if isinstance(stats, dict) else 0
    suspicious = int(float(stats.get("suspicious", 0) or 0)) if isinstance(stats, dict) else 0
    harmless = int(float(stats.get("harmless", 0) or 0)) if isinstance(stats, dict) else 0
    undetected = int(float(stats.get("undetected", 0) or 0)) if isinstance(stats, dict) else 0

    total = malicious + suspicious + harmless + undetected
    score = round((malicious / total) * 100) if total > 0 else 0

    if malicious > 0:
        status = "malicious"
    elif suspicious > 0:
        status = "suspicious"
    elif harmless > 0:
        status = "clean"
    else:
        status = "unknown"

    details: dict[str, Any] = {
        "stats": stats if isinstance(stats, dict) else {},
        "enginesTotal": total,
        "maliciousCount": malicious,
    }
    if ioc_type == IOC_TYPE_IP:
        details["meta"] = {
            "country": attrs.get("country") if isinstance(attrs, dict) else None,
            "asn": attrs.get("asn") if isinstance(attrs, dict) else None,
            "asnOwner": attrs.get("as_owner") if isinstance(attrs, dict) else None,
        }

    return make_provider_result("virustotal", status=status, score=score, details=details)


def abuseipdb_lookup(value: str, api_key: str | None = None) -> dict[str, Any]:
    resolved_api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
    if not resolved_api_key:
        return make_provider_result(
            "abuseipdb",
            status="error",
            score=0,
            details={},
            error="Missing AbuseIPDB API key",
        )

    ip_str = str(value or "").strip()
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return make_provider_result(
            "abuseipdb",
            status="unknown",
            score=0,
            details={
                "skipped": True,
                "reason": "unsupported_ioc_type",
                "supported_types": ["ip"],
            },
        )

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": resolved_api_key,
                "Accept": "application/json",
            },
            params={"ipAddress": ip_str, "maxAgeInDays": 365},
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        return make_provider_result(
            "abuseipdb",
            status="error",
            score=0,
            details={},
            error=f"AbuseIPDB API error: {exc}",
        )
    except ValueError:
        return make_provider_result(
            "abuseipdb",
            status="error",
            score=0,
            details={},
            error="AbuseIPDB API error: Invalid JSON response",
        )

    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    score = int(float(data.get("abuseConfidenceScore", 0) or 0))
    if score >= 75:
        status = "malicious"
    elif score >= 25:
        status = "suspicious"
    elif score >= 1:
        status = "clean"
    else:
        status = "unknown"

    return make_provider_result(
        "abuseipdb",
        status=status,
        score=score,
        details={
            "confidence": score,
            "reports": int(float(data.get("totalReports", 0) or 0)),
            "countryCode": data.get("countryCode") or None,
            "isp": data.get("isp") or None,
            "domain": data.get("domain") or None,
            "lastReportedAt": data.get("lastReportedAt") or None,
        },
    )


def otx_lookup(value: str, ioc_type: str, api_key: str | None = None) -> dict[str, Any]:
    resolved_api_key = api_key or os.getenv("OTX_API_KEY")
    if not resolved_api_key:
        return make_provider_result(
            "otx",
            status="error",
            score=0,
            details={},
            error="Missing OTX API key",
        )

    raw_value = str(value or "")
    if ioc_type == IOC_TYPE_IP:
        endpoint = f"/api/v1/indicators/IPv4/{quote(raw_value, safe='')}/general"
    elif ioc_type == IOC_TYPE_DOMAIN:
        endpoint = f"/api/v1/indicators/domain/{quote(raw_value, safe='')}/general"
    elif ioc_type == IOC_TYPE_HASH:
        endpoint = f"/api/v1/indicators/file/{quote(raw_value, safe='')}/general"
    elif ioc_type == IOC_TYPE_URL:
        try:
            parsed = urlparse(raw_value)
            if not parsed.hostname:
                raise ValueError("missing hostname")
            endpoint = f"/api/v1/indicators/domain/{quote(parsed.hostname, safe='')}/general"
        except ValueError:
            return make_provider_result(
                "otx",
                status="unknown",
                score=0,
                details={
                    "skipped": True,
                    "reason": "unsupported_ioc_type",
                    "supported_types": ["ip", "domain", "hash", "url"],
                },
            )
    else:
        return make_provider_result(
            "otx",
            status="unknown",
            score=0,
            details={
                "skipped": True,
                "reason": "unsupported_ioc_type",
                "supported_types": ["ip", "domain", "hash", "url"],
            },
        )

    try:
        response = requests.get(
            f"https://otx.alienvault.com{endpoint}",
            headers={"X-OTX-API-KEY": resolved_api_key},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.HTTPError as exc:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        if status_code == 404:
            return make_provider_result(
                "otx",
                status="unknown",
                score=0,
                details={"pulses": 0, "reputation": 0, "summary": "No OTX indicator match"},
            )
        if status_code == 403:
            return make_provider_result(
                "otx",
                status="error",
                score=0,
                details={},
                error="Invalid OTX API key or access denied",
            )
        if status_code == 429:
            return make_provider_result(
                "otx",
                status="error",
                score=0,
                details={},
                error="OTX API rate limit exceeded",
            )
        return make_provider_result(
            "otx",
            status="error",
            score=0,
            details={},
            error=f"OTX API error: {exc}",
        )
    except requests.RequestException as exc:
        return make_provider_result(
            "otx",
            status="error",
            score=0,
            details={},
            error=f"OTX API error: {exc}",
        )
    except ValueError:
        return make_provider_result(
            "otx",
            status="error",
            score=0,
            details={},
            error="OTX API error: Invalid JSON response",
        )

    pulses = int(float(payload.get("pulse_info", {}).get("count", 0) or 0)) if isinstance(payload, dict) else 0
    reputation = int(float(payload.get("reputation", 0) or 0)) if isinstance(payload, dict) else 0

    score = 0
    if pulses > 0:
        score = min(100, 20 + min(80, pulses * 5))
    if reputation < 0:
        score = max(score, min(100, 50 + abs(reputation) * 5))

    if score >= 75:
        status = "malicious"
    elif score >= 35:
        status = "suspicious"
    elif score > 0:
        status = "clean"
    else:
        status = "unknown"

    return make_provider_result(
        "otx",
        status=status,
        score=score,
        details={"pulses": pulses, "reputation": reputation},
    )


def threatfox_lookup(value: str, ioc_type: str, api_key: str | None = None) -> dict[str, Any]:
    resolved_api_key = api_key or os.getenv("THREATFOX_API_KEY")
    if not resolved_api_key:
        return make_provider_result(
            "threatfox",
            status="error",
            score=0,
            details={},
            error="ThreatFox API key required. Get one free at auth.abuse.ch",
        )

    if ioc_type not in {IOC_TYPE_IP, IOC_TYPE_DOMAIN, IOC_TYPE_URL, IOC_TYPE_HASH}:
        return make_provider_result(
            "threatfox",
            status="unknown",
            score=0,
            details={
                "skipped": True,
                "reason": "unsupported_ioc_type",
                "supported_types": ["ip", "domain", "url", "hash"],
            },
        )

    raw_value = str(value)
    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={
                "Auth-Key": resolved_api_key,
                "Content-Type": "application/json",
            },
            json={
                "query": "search_ioc",
                "search_term": raw_value,
                "exact_match": ioc_type != IOC_TYPE_IP,
            },
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.HTTPError as exc:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        if status_code in {401, 403}:
            return make_provider_result(
                "threatfox",
                status="error",
                score=0,
                details={},
                error="Invalid ThreatFox API key or access denied",
            )
        if status_code == 429:
            return make_provider_result(
                "threatfox",
                status="error",
                score=0,
                details={},
                error="ThreatFox API rate limit exceeded",
            )
        if isinstance(status_code, int) and status_code >= 500:
            return make_provider_result(
                "threatfox",
                status="error",
                score=0,
                details={},
                error="ThreatFox service temporarily unavailable",
            )
        return make_provider_result(
            "threatfox",
            status="error",
            score=0,
            details={},
            error=f"ThreatFox API error: {exc}",
        )
    except requests.RequestException as exc:
        return make_provider_result(
            "threatfox",
            status="error",
            score=0,
            details={},
            error=f"ThreatFox API error: {exc}",
        )
    except ValueError:
        return make_provider_result(
            "threatfox",
            status="error",
            score=0,
            details={},
            error="ThreatFox API error: Invalid JSON response",
        )

    if not isinstance(payload, dict):
        return make_provider_result("threatfox", status="unknown", score=0, details={"query_status": None})

    query_status = payload.get("query_status")
    if query_status != "ok":
        if query_status == "no_result":
            return make_provider_result("threatfox", status="unknown", score=0, details={"count": 0})
        return make_provider_result(
            "threatfox", status="unknown", score=0, details={"query_status": query_status}
        )

    entries_raw = payload.get("data")
    entries = entries_raw if isinstance(entries_raw, list) else []
    if not entries:
        return make_provider_result("threatfox", status="unknown", score=0, details={"count": 0})

    relevant_entries = entries
    if ioc_type == IOC_TYPE_IP:
        ip_value = raw_value
        relevant_entries = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            entry_ioc = str(entry.get("ioc", ""))
            if entry_ioc == ip_value or entry_ioc.startswith(f"{ip_value}:"):
                relevant_entries.append(entry)

    if not relevant_entries:
        return make_provider_result("threatfox", status="unknown", score=0, details={"count": 0})

    confidences: list[int] = []
    for entry in relevant_entries:
        if not isinstance(entry, dict):
            continue
        try:
            confidence = int(float(entry.get("confidence_level", 0)))
            confidences.append(confidence)
        except (TypeError, ValueError):
            continue

    score = round(sum(confidences) / len(confidences)) if confidences else 50
    if score >= 80:
        status = "malicious"
    elif score >= 50:
        status = "suspicious"
    else:
        status = "clean"

    first_entry = next((entry for entry in relevant_entries if isinstance(entry, dict)), {})
    details = {
        "count": len(relevant_entries),
        "confidences": confidences,
        "foundIOCs": [str(entry.get("ioc")) for entry in relevant_entries if isinstance(entry, dict)][:3],
    }
    if isinstance(first_entry, dict):
        details["malware"] = first_entry.get("malware") or None
        details["threat_type"] = first_entry.get("threat_type") or None
        details["ioc_type"] = first_entry.get("ioc_type_desc") or first_entry.get("ioc_type") or None
        details["tags"] = first_entry.get("tags") if isinstance(first_entry.get("tags"), list) else []
        details["first_seen"] = first_entry.get("first_seen") or None
        details["last_seen"] = first_entry.get("last_seen") or None
        details["reporter"] = first_entry.get("reporter") or None
        details["reference"] = first_entry.get("reference") or None

    return make_provider_result("threatfox", status=status, score=score, details=details)


def _enabled_providers(providers: dict[str, bool] | None) -> dict[str, bool]:
    if not providers:
        return {
            "virustotal": True,
            "abuseipdb": True,
            "otx": True,
            "threatfox": True,
        }
    return {name: bool(enabled) for name, enabled in providers.items()}


def _aggregate_status(provider_results: dict[str, dict[str, Any]]) -> str:
    statuses = [result.get("status", "unknown") for result in provider_results.values()]
    if "malicious" in statuses:
        return "malicious"
    if "suspicious" in statuses:
        return "suspicious"
    if "clean" in statuses:
        return "clean"
    return "unknown"


def _aggregate_score(provider_results: dict[str, dict[str, Any]]) -> int:
    scores = [
        result.get("score")
        for result in provider_results.values()
        if isinstance(result.get("score"), (int, float))
    ]
    if not scores:
        return 0
    return round(sum(scores) / len(scores))


def _normalize_provider_result(
    provider_name: str,
    result: dict[str, Any],
    ioc: str,
    ioc_type: str,
) -> dict[str, Any]:
    status = result.get("status", "unknown")
    normalized_status = status if status in VALID_PROVIDER_STATUSES else "error"
    score_raw = result.get("score", 0)
    score = int(score_raw) if isinstance(score_raw, (int, float)) else 0
    details = result.get("details")
    normalized: dict[str, Any] = {
        "provider": provider_name,
        "ioc": ioc,
        "type": ioc_type,
        "status": normalized_status,
        "score": score,
        "details": details if isinstance(details, dict) else {},
    }
    if result.get("error") is not None:
        normalized["error"] = str(result.get("error"))
    return normalized


def scan_ioc(
    value: str,
    providers: dict[str, bool] | None = None,
    api_keys: dict[str, str] | None = None,
) -> dict[str, Any]:
    raw = str(value)
    ioc_type = detect_ioc_type(raw)

    if ioc_type == IOC_TYPE_UNKNOWN:
        return {
            "ioc": raw,
            "type": IOC_TYPE_UNKNOWN,
            "status": "invalid",
            "score": 0,
            "providers": {},
            "errors": ["Invalid IOC"],
        }

    enabled = _enabled_providers(providers)
    keys = api_keys or {}
    provider_results: dict[str, dict[str, Any]] = {}

    if enabled.get("virustotal"):
        provider_results["virustotal"] = _normalize_provider_result(
            "virustotal",
            vt_lookup(raw, ioc_type, keys.get("virustotal")),
            raw,
            ioc_type,
        )

    if enabled.get("abuseipdb") and ioc_type == IOC_TYPE_IP:
        provider_results["abuseipdb"] = _normalize_provider_result(
            "abuseipdb",
            abuseipdb_lookup(raw, keys.get("abuseipdb")),
            raw,
            ioc_type,
        )

    if enabled.get("otx"):
        provider_results["otx"] = _normalize_provider_result(
            "otx",
            otx_lookup(raw, ioc_type, keys.get("otx")),
            raw,
            ioc_type,
        )

    if enabled.get("threatfox"):
        provider_results["threatfox"] = _normalize_provider_result(
            "threatfox",
            threatfox_lookup(raw, ioc_type, keys.get("threatfox")),
            raw,
            ioc_type,
        )

    return {
        "ioc": raw,
        "type": ioc_type,
        "status": _aggregate_status(provider_results),
        "score": _aggregate_score(provider_results),
        "providers": provider_results,
    }
