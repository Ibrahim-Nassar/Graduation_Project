from __future__ import annotations

import base64
import ipaddress
import re
from urllib.parse import quote
from typing import Any

import requests

IOC_TYPE_IP = "ip"
IOC_TYPE_DOMAIN = "domain"
IOC_TYPE_URL = "url"
IOC_TYPE_HASH = "hash"
IOC_TYPE_UNKNOWN = "unknown"

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_TIMEOUT_SECONDS = 8


def detect_ioc_type(value: str) -> str:
    ioc = value.strip()
    if not ioc:
        return IOC_TYPE_UNKNOWN
    if _IP_RE.match(ioc):
        try:
            ipaddress.ip_address(ioc)
            return IOC_TYPE_IP
        except ValueError:
            return IOC_TYPE_UNKNOWN
    if _URL_RE.match(ioc):
        return IOC_TYPE_URL
    if _HASH_RE.match(ioc):
        return IOC_TYPE_HASH
    if _DOMAIN_RE.match(ioc):
        return IOC_TYPE_DOMAIN
    return IOC_TYPE_UNKNOWN


def _enabled_providers(providers: dict[str, bool] | None) -> dict[str, bool]:
    defaults = {"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True}
    if providers is None:
        return defaults
    for name in list(defaults.keys()):
        defaults[name] = bool(providers.get(name, defaults[name]))
    return defaults


def _aggregate_status(provider_results: dict[str, dict[str, Any]]) -> str:
    statuses = [str((payload or {}).get("status", "unknown")).lower() for payload in provider_results.values()]
    if "malicious" in statuses:
        return "malicious"
    if "suspicious" in statuses:
        return "suspicious"
    if "clean" in statuses:
        return "clean"
    if statuses and all(status in {"not_found", "n/a"} for status in statuses):
        return "unknown"
    if statuses:
        return "unknown"
    return "unknown"


def _aggregate_score(provider_results: dict[str, dict[str, Any]]) -> int:
    if not provider_results:
        return 0
    score_map = {"malicious": 90, "suspicious": 65, "clean": 10, "unknown": 0, "n/a": 0, "not_found": 0}
    scores = [
        score_map.get(str((payload or {}).get("status", "unknown")).lower(), 0)
        for payload in provider_results.values()
    ]
    return int(round(sum(scores) / max(len(scores), 1)))


def _normalize_provider_result(
    provider_name: str,
    payload: dict[str, Any] | None,
    ioc: str,
    ioc_type: str,
) -> dict[str, Any]:
    result = dict(payload or {})
    result.setdefault("provider", provider_name)
    result.setdefault("ioc", ioc)
    result.setdefault("type", ioc_type)
    result.setdefault("status", "n/a")
    result.setdefault("score", 0)
    return result


def _http_get_json(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    response = requests.get(url, headers=headers or {}, timeout=_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def _http_post_json(
    url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None
) -> dict[str, Any]:
    response = requests.post(url, json=payload, headers=headers or {}, timeout=_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def vt_lookup(ioc: str, ioc_type: str, api_key: str | None) -> dict[str, Any]:
    key = (api_key or "").strip()
    if not key:
        return {"status": "n/a", "score": 0, "error": "missing API key"}

    endpoint: str
    if ioc_type == IOC_TYPE_IP:
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{quote(ioc)}"
    elif ioc_type == IOC_TYPE_DOMAIN:
        endpoint = f"https://www.virustotal.com/api/v3/domains/{quote(ioc)}"
    elif ioc_type == IOC_TYPE_HASH:
        endpoint = f"https://www.virustotal.com/api/v3/files/{quote(ioc)}"
    elif ioc_type == IOC_TYPE_URL:
        encoded = base64.urlsafe_b64encode(ioc.encode("utf-8")).decode("utf-8").rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"
    else:
        return {"status": "unknown", "score": 0, "error": f"unsupported IOC type: {ioc_type}"}

    headers = {"x-apikey": key}
    try:
        payload = _http_get_json(endpoint, headers=headers)
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "http_error"
        return {"status": "error", "score": 0, "error": f"http {code}"}
    except Exception as exc:
        return {"status": "error", "score": 0, "error": str(exc)}

    stats = (((payload.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    if malicious > 0:
        return {"status": "malicious", "score": min(100, 80 + malicious), "details": stats}
    if suspicious > 0:
        return {"status": "suspicious", "score": min(79, 50 + suspicious), "details": stats}
    if harmless > 0:
        return {"status": "clean", "score": 10, "details": stats}
    return {"status": "unknown", "score": 0, "details": stats}


def abuseipdb_lookup(ioc: str, api_key: str | None) -> dict[str, Any]:
    key = (api_key or "").strip()
    if not key:
        return {"status": "n/a", "score": 0, "error": "missing API key"}

    endpoint = f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ioc)}&maxAgeInDays=90"
    headers = {"Accept": "application/json", "Key": key}
    try:
        payload = _http_get_json(endpoint, headers=headers)
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "http_error"
        return {"status": "error", "score": 0, "error": f"http {code}"}
    except Exception as exc:
        return {"status": "error", "score": 0, "error": str(exc)}

    data = payload.get("data", {})
    confidence = int(data.get("abuseConfidenceScore", 0) or 0)
    reports = int(data.get("totalReports", 0) or 0)
    if confidence >= 75:
        return {"status": "malicious", "score": confidence, "details": {"confidence": confidence, "reports": reports}}
    if confidence >= 25:
        return {"status": "suspicious", "score": confidence, "details": {"confidence": confidence, "reports": reports}}
    return {"status": "clean", "score": confidence, "details": {"confidence": confidence, "reports": reports}}


def otx_lookup(ioc: str, ioc_type: str, api_key: str | None) -> dict[str, Any]:
    key = (api_key or "").strip()
    if not key:
        return {"status": "n/a", "score": 0, "error": "missing API key"}

    otx_type = {
        IOC_TYPE_IP: "IPv4",
        IOC_TYPE_DOMAIN: "domain",
        IOC_TYPE_URL: "url",
        IOC_TYPE_HASH: "file",
    }.get(ioc_type)
    if not otx_type:
        return {"status": "unknown", "score": 0, "error": f"unsupported IOC type: {ioc_type}"}

    endpoint = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{quote(ioc)}/general"
    headers = {"X-OTX-API-KEY": key}
    try:
        payload = _http_get_json(endpoint, headers=headers)
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "http_error"
        return {"status": "error", "score": 0, "error": f"http {code}"}
    except Exception as exc:
        return {"status": "error", "score": 0, "error": str(exc)}

    pulse_count = int((((payload.get("pulse_info") or {}).get("count", 0)) or 0))
    if pulse_count >= 10:
        return {"status": "malicious", "score": min(100, 70 + pulse_count), "details": {"pulses": pulse_count}}
    if pulse_count > 0:
        return {"status": "suspicious", "score": min(79, 40 + pulse_count), "details": {"pulses": pulse_count}}
    return {"status": "clean", "score": 10, "details": {"pulses": 0}}


def threatfox_lookup(ioc: str, ioc_type: str, api_key: str | None) -> dict[str, Any]:
    _ = ioc_type
    key = (api_key or "").strip()
    if not key:
        return {"status": "n/a", "score": 0, "error": "missing API key"}

    endpoint = "https://threatfox-api.abuse.ch/api/v1/"
    normalized_ioc = ioc.strip()
    attempts = [
        {"query": "search_ioc", "search_term": f"ioc:{normalized_ioc}"},
        {"query": "search_ioc", "search_term": normalized_ioc},
    ]
    headers = {"Auth-Key": key, "Accept": "application/json"}
    last_error = ""
    for payload in attempts:
        try:
            response = _http_post_json(endpoint, payload=payload, headers=headers)
        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "http_error"
            return {"status": "error", "score": 0, "error": f"http {code}"}
        except Exception as exc:
            return {"status": "error", "score": 0, "error": str(exc)}

        status = str(response.get("query_status", "no_result")).lower()
        message = str(response.get("error") or response.get("message") or "").strip()
        if status == "ok":
            rows = response.get("data") or []
            if rows:
                break
            continue
        if status in {"ok_no_results", "no_result"}:
            continue

        error_text = f"query_status:{status}"
        if message:
            error_text += f" ({message})"
        last_error = error_text
    else:
        if last_error:
            return {"status": "error", "score": 0, "error": last_error}
        return {
            "status": "not_found",
            "score": 0,
            "details": {"matches": 0, "query_status": "no_result", "search_term": attempts[0]["search_term"]},
        }

    max_confidence = 0
    for row in rows:
        confidence = int((row or {}).get("confidence_level", 0) or 0)
        if confidence > max_confidence:
            max_confidence = confidence

    if max_confidence >= 75:
        return {
            "status": "malicious",
            "score": max_confidence,
            "details": {"matches": len(rows), "search_term": str(payload["search_term"])},
        }
    return {
        "status": "suspicious",
        "score": max(30, max_confidence),
        "details": {"matches": len(rows), "search_term": str(payload["search_term"])},
    }


def scan_ioc(
    value: str,
    *,
    providers: dict[str, bool] | None = None,
    api_keys: dict[str, str] | None = None,
) -> dict[str, Any]:
    ioc = value.strip()
    ioc_type = detect_ioc_type(ioc)
    enabled = _enabled_providers(providers)
    keys = api_keys or {}

    provider_results: dict[str, dict[str, Any]] = {}
    if enabled.get("virustotal"):
        provider_results["virustotal"] = _normalize_provider_result(
            "virustotal",
            vt_lookup(ioc, ioc_type, keys.get("virustotal")),
            ioc,
            ioc_type,
        )
    if enabled.get("abuseipdb") and ioc_type == IOC_TYPE_IP:
        provider_results["abuseipdb"] = _normalize_provider_result(
            "abuseipdb",
            abuseipdb_lookup(ioc, keys.get("abuseipdb")),
            ioc,
            ioc_type,
        )
    if enabled.get("otx"):
        provider_results["otx"] = _normalize_provider_result(
            "otx",
            otx_lookup(ioc, ioc_type, keys.get("otx")),
            ioc,
            ioc_type,
        )
    if enabled.get("threatfox"):
        provider_results["threatfox"] = _normalize_provider_result(
            "threatfox",
            threatfox_lookup(ioc, ioc_type, keys.get("threatfox")),
            ioc,
            ioc_type,
        )

    status = _aggregate_status(provider_results)
    score = _aggregate_score(provider_results)
    return {
        "ioc": ioc,
        "type": ioc_type,
        "status": status,
        "score": score,
        "providers": provider_results,
        "errors": [],
    }
