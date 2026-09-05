from __future__ import annotations

import base64
import ipaddress
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlsplit
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
_SCAN_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_LOCK = threading.Lock()
_MAX_CACHE_SIZE = 500


def _cache_key(ioc: str, providers: dict[str, bool] | None) -> str:
    enabled = _enabled_providers(providers)
    active = sorted(k for k, v in enabled.items() if v)
    return f"{ioc.strip().lower()}|{'|'.join(active)}"


def clear_scan_cache() -> None:
    with _CACHE_LOCK:
        _SCAN_CACHE.clear()


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
    if statuses and all(s == "auth_error" for s in statuses):
        return "auth_error"
    if statuses and all(s in {"not_found", "n/a", "auth_error"} for s in statuses):
        return "unknown"
    if statuses:
        return "unknown"
    return "unknown"


ASSESSMENT_CORROBORATED_MALICIOUS = "corroborated_malicious"
ASSESSMENT_PROVIDERS_DISAGREE = "providers_disagree"
ASSESSMENT_SINGLE_SOURCE_MALICIOUS = "single_source_malicious"
ASSESSMENT_SUSPICIOUS_ONLY = "suspicious_only"
ASSESSMENT_NO_SUSPICIOUS_FINDINGS = "no_suspicious_findings"
ASSESSMENT_INSUFFICIENT_DATA = "insufficient_data"

ASSESSMENT_VALUES: tuple[str, ...] = (
    ASSESSMENT_CORROBORATED_MALICIOUS,
    ASSESSMENT_PROVIDERS_DISAGREE,
    ASSESSMENT_SINGLE_SOURCE_MALICIOUS,
    ASSESSMENT_SUSPICIOUS_ONLY,
    ASSESSMENT_NO_SUSPICIOUS_FINDINGS,
    ASSESSMENT_INSUFFICIENT_DATA,
)


def _provider_reason(name: str, payload: dict[str, Any], status: str) -> str:
    if name == "virustotal":
        details = payload.get("details")
        if isinstance(details, dict) and "vendor_total" in details:
            malicious = int(details.get("malicious", 0) or 0)
            vendor_total = int(details.get("vendor_total", 0) or 0)
            return f"{name}: {status} ({malicious}/{vendor_total} vendors)"
    return f"{name}: {status}"


def compute_verdict(provider_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Produce a categorical assessment from all provider results.

    Returns a dict with ``assessment`` (one of :data:`ASSESSMENT_VALUES`),
    ``reasoning`` (which providers responded and what each said), plus the
    provider-name lists ``responding``, ``malicious``, ``suspicious`` and
    ``clean``.  There is deliberately no numeric field: the assessment says
    how the providers agreed, not how "confident" the tool is.
    """
    malicious: list[str] = []
    suspicious: list[str] = []
    clean: list[str] = []
    responding: list[str] = []
    reasons: list[str] = []

    for name, payload in (provider_results or {}).items():
        payload = payload or {}
        status = str(payload.get("status", "unknown")).lower()
        if status == "malicious":
            malicious.append(name)
        elif status == "suspicious":
            suspicious.append(name)
        elif status == "clean":
            clean.append(name)
        else:
            continue
        responding.append(name)
        reasons.append(_provider_reason(name, payload, status))

    if len(malicious) >= 2:
        assessment = ASSESSMENT_CORROBORATED_MALICIOUS
    elif (malicious or suspicious) and clean:
        assessment = ASSESSMENT_PROVIDERS_DISAGREE
    elif len(malicious) == 1 and not clean:
        assessment = ASSESSMENT_SINGLE_SOURCE_MALICIOUS
    elif suspicious and not malicious and not clean:
        assessment = ASSESSMENT_SUSPICIOUS_ONLY
    elif responding and len(clean) == len(responding):
        assessment = ASSESSMENT_NO_SUSPICIOUS_FINDINGS
    else:
        assessment = ASSESSMENT_INSUFFICIENT_DATA

    if reasons:
        reasoning = "; ".join(reasons) + "."
    else:
        reasoning = "No provider returned a usable result."

    return {
        "assessment": assessment,
        "reasoning": reasoning,
        "responding": responding,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean,
    }


_NON_PUBLIC_DOMAIN_LABELS = frozenset({
    "local", "localdomain", "internal", "intranet", "lan", "corp", "home",
    "localhost", "test", "example", "invalid",
})


def _is_public_host(host: str) -> tuple[bool, str]:
    candidate = host.strip().strip("[]").lower()
    if not candidate:
        return False, "non_public_domain"
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        if address.is_global:
            return True, ""
        return False, "private_or_reserved_ip"
    if "." not in candidate or candidate.rstrip(".").split(".")[-1] in _NON_PUBLIC_DOMAIN_LABELS:
        return False, "non_public_domain"
    return True, ""


def is_scannable_ioc(value: str, ioc_type: str) -> tuple[bool, str]:
    """Return ``(True, "")`` when ``value`` may be sent to external providers.

    Private / reserved IPs, non-public domain suffixes (``.local``,
    ``.corp`` ...) and URLs whose host fails those rules must never leave
    the workstation.  Hashes carry no network information and are always
    scannable.  When not scannable the second element names the reason.
    """
    ioc = value.strip()
    if ioc_type == IOC_TYPE_HASH:
        return True, ""
    if ioc_type == IOC_TYPE_IP:
        try:
            if ipaddress.ip_address(ioc).is_global:
                return True, ""
        except ValueError:
            pass
        return False, "private_or_reserved_ip"
    if ioc_type == IOC_TYPE_DOMAIN:
        return _is_public_host(ioc)
    if ioc_type == IOC_TYPE_URL:
        try:
            host = urlsplit(ioc).hostname or ""
        except ValueError:
            host = ""
        return _is_public_host(host)
    return True, ""


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


_AUTH_FAILURE_CODES = frozenset({401, 403})


def _classify_http_error(exc: requests.HTTPError, provider: str) -> dict[str, Any]:
    code = exc.response.status_code if exc.response is not None else None
    if code in _AUTH_FAILURE_CODES:
        return {
            "status": "auth_error",
            "score": 0,
            "error": f"invalid or expired API key ({provider}, HTTP {code})",
        }
    label = f"http {code}" if code is not None else "http_error"
    return {"status": "error", "score": 0, "error": label}


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
        return _classify_http_error(exc, "virustotal")
    except Exception as exc:
        return {"status": "error", "score": 0, "error": str(exc)}

    stats = (((payload.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    details = stats
    details["vendor_total"] = malicious + suspicious + harmless + undetected
    if malicious >= 3:
        return {"status": "malicious", "score": min(100, 80 + malicious), "details": details}
    if 1 <= malicious < 3 or suspicious > 0:
        return {"status": "suspicious", "score": min(79, 50 + suspicious), "details": details}
    if malicious == 0 and suspicious == 0 and harmless > 0:
        return {"status": "clean", "score": 10, "details": details}
    return {"status": "unknown", "score": 0, "details": details}


def abuseipdb_lookup(ioc: str, api_key: str | None) -> dict[str, Any]:
    key = (api_key or "").strip()
    if not key:
        return {"status": "n/a", "score": 0, "error": "missing API key"}

    endpoint = f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ioc)}&maxAgeInDays=90"
    headers = {"Accept": "application/json", "Key": key}
    try:
        payload = _http_get_json(endpoint, headers=headers)
    except requests.HTTPError as exc:
        return _classify_http_error(exc, "abuseipdb")
    except Exception as exc:
        return {"status": "error", "score": 0, "error": str(exc)}

    data = payload.get("data", {})
    confidence = int(data.get("abuseConfidenceScore", 0) or 0)
    reports = int(data.get("totalReports", 0) or 0)
    # AbuseIPDB's abuseConfidenceScore is a *community noise* signal: public
    # IPs routinely pick up a handful of low-effort reports without being
    # malicious.  Keep "malicious" at the original 75 but raise "suspicious"
    # to 40 (with >=2 reports) so benign public IPs aren't easily flagged.
    if confidence >= 75:
        return {"status": "malicious", "score": confidence, "details": {"confidence": confidence, "reports": reports}}
    if confidence >= 40 and reports >= 2:
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
        return _classify_http_error(exc, "otx")
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
            return _classify_http_error(exc, "threatfox")
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
    scannable, skip_reason = is_scannable_ioc(ioc, ioc_type)
    if not scannable:
        # Private / internal indicators never leave the workstation: no
        # provider call is made and nothing is cached.
        return {
            "ioc": ioc,
            "type": ioc_type,
            "status": "skipped",
            "reason": skip_reason,
            "providers": {},
            "verdict": compute_verdict({}),
            "errors": [],
        }

    cache_k = _cache_key(ioc, providers)
    with _CACHE_LOCK:
        if cache_k in _SCAN_CACHE:
            return dict(_SCAN_CACHE[cache_k])

    enabled = _enabled_providers(providers)
    keys = api_keys or {}

    tasks: list[tuple[str, Any]] = []
    if enabled.get("virustotal"):
        tasks.append(("virustotal", lambda: vt_lookup(ioc, ioc_type, keys.get("virustotal"))))
    if enabled.get("abuseipdb") and ioc_type == IOC_TYPE_IP:
        tasks.append(("abuseipdb", lambda: abuseipdb_lookup(ioc, keys.get("abuseipdb"))))
    if enabled.get("otx"):
        tasks.append(("otx", lambda: otx_lookup(ioc, ioc_type, keys.get("otx"))))
    if enabled.get("threatfox"):
        tasks.append(("threatfox", lambda: threatfox_lookup(ioc, ioc_type, keys.get("threatfox"))))

    provider_results: dict[str, dict[str, Any]] = {}
    if len(tasks) <= 1:
        for name, fn in tasks:
            try:
                provider_results[name] = _normalize_provider_result(name, fn(), ioc, ioc_type)
            except Exception as exc:
                provider_results[name] = _normalize_provider_result(
                    name, {"status": "error", "score": 0, "error": str(exc)}, ioc, ioc_type,
                )
    else:
        with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            future_map = {pool.submit(fn): name for name, fn in tasks}
            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"status": "error", "score": 0, "error": str(exc)}
                provider_results[name] = _normalize_provider_result(name, result, ioc, ioc_type)

    status = _aggregate_status(provider_results)
    verdict = compute_verdict(provider_results)
    output = {
        "ioc": ioc,
        "type": ioc_type,
        "status": status,
        "verdict": verdict,
        "providers": provider_results,
        "errors": [],
    }

    with _CACHE_LOCK:
        if len(_SCAN_CACHE) < _MAX_CACHE_SIZE:
            _SCAN_CACHE[cache_k] = dict(output)
    return output
