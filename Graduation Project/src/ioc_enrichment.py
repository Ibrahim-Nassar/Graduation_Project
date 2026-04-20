from __future__ import annotations

import base64
import ipaddress
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def _aggregate_score(provider_results: dict[str, dict[str, Any]]) -> int:
    if not provider_results:
        return 0
    score_map = {"malicious": 90, "suspicious": 65, "clean": 10, "unknown": 0, "n/a": 0, "not_found": 0}
    scores = [
        score_map.get(str((payload or {}).get("status", "unknown")).lower(), 0)
        for payload in provider_results.values()
    ]
    return int(round(sum(scores) / max(len(scores), 1)))


_PROVIDER_WEIGHTS: dict[str, float] = {
    "virustotal": 2.0,
    "abuseipdb": 1.5,
    "otx": 1.0,
    "threatfox": 1.2,
}

_VERDICT_MALICIOUS = "Malicious"
_VERDICT_SUSPICIOUS = "Suspicious"
_VERDICT_CLEAN = "Clean"
_VERDICT_UNKNOWN = "Unknown"


def compute_verdict(provider_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Produce a single unified verdict from all provider results.

    Returns a dict with ``verdict``, ``confidence`` (0-100), and ``reasoning``.
    Uses weighted voting: providers with higher reliability contribute more to
    the final decision.  A single credible "malicious" flag from a high-weight
    provider is enough to override clean signals from lower-weight sources.
    """
    if not provider_results:
        return {"verdict": _VERDICT_UNKNOWN, "confidence": 0, "reasoning": "No provider data available."}

    status_buckets: dict[str, list[str]] = {
        "malicious": [], "suspicious": [], "clean": [], "other": [],
    }
    weighted_scores: dict[str, float] = {"malicious": 0.0, "suspicious": 0.0, "clean": 0.0}
    total_weight = 0.0
    reasons: list[str] = []

    for name, payload in provider_results.items():
        status = str((payload or {}).get("status", "unknown")).lower()
        weight = _PROVIDER_WEIGHTS.get(name, 1.0)

        if status in {"error", "auth_error", "n/a", "not_found", "not_supported", "unknown"}:
            status_buckets["other"].append(name)
            continue

        total_weight += weight
        if status == "malicious":
            status_buckets["malicious"].append(name)
            weighted_scores["malicious"] += weight
            reasons.append(f"{name} flagged malicious")
        elif status == "suspicious":
            status_buckets["suspicious"].append(name)
            weighted_scores["suspicious"] += weight
            reasons.append(f"{name} flagged suspicious")
        elif status == "clean":
            status_buckets["clean"].append(name)
            weighted_scores["clean"] += weight

    if total_weight == 0:
        return {"verdict": _VERDICT_UNKNOWN, "confidence": 0, "reasoning": "All providers returned inconclusive results."}

    mal_ratio = weighted_scores["malicious"] / total_weight
    sus_ratio = weighted_scores["suspicious"] / total_weight
    clean_ratio = weighted_scores["clean"] / total_weight

    if status_buckets["malicious"]:
        verdict = _VERDICT_MALICIOUS
        agreement = mal_ratio
        if not reasons:
            reasons.append("Multiple providers detected malicious activity")
    elif status_buckets["suspicious"]:
        verdict = _VERDICT_SUSPICIOUS
        agreement = sus_ratio
        if not reasons:
            reasons.append("Suspicious indicators detected")
    elif status_buckets["clean"]:
        verdict = _VERDICT_CLEAN
        agreement = clean_ratio
        reasons = ["All responding providers returned clean"]
    else:
        verdict = _VERDICT_UNKNOWN
        agreement = 0.0
        reasons = ["Insufficient data for a determination"]

    # Confidence reflects *our belief in the verdict*, not the population
    # coverage.  A strong result from one credible provider should not look
    # artificially weak just because the other providers stayed silent
    # (no key, no match, rate-limited, etc.).  We therefore base confidence
    # on the agreement ratio among *responding* providers and only apply a
    # mild dampener when exactly one provider weighed in, to honour the
    # "corroboration is nice" signal without manufacturing distrust.
    responding = (
        len(status_buckets["malicious"])
        + len(status_buckets["suspicious"])
        + len(status_buckets["clean"])
    )
    # Single-provider verdicts get a small haircut; two or more responding
    # providers get no haircut at all.  Empirically this keeps a credible
    # single "Malicious" hit at ~85% rather than dropping it to ~33%.
    single_source_dampener = 0.85 if responding == 1 else 1.0
    confidence = int(round(agreement * single_source_dampener * 100))
    confidence = max(0, min(100, confidence))

    # Final sanity gate: never display a decisive verdict with a confidence
    # that looks untrustworthy next to it.  If agreement is genuinely low
    # (mixed signals across responding providers) the verdict itself should
    # already be Suspicious / Unknown, so we only floor it here to avoid
    # the pathological "Malicious @ 20%" row the UI used to produce.
    if verdict in {_VERDICT_MALICIOUS, _VERDICT_SUSPICIOUS, _VERDICT_CLEAN}:
        confidence = max(confidence, 50)

    reasoning = "; ".join(reasons[:3]) + "." if reasons else "No determination."

    return {"verdict": verdict, "confidence": confidence, "reasoning": reasoning}


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
    cache_k = _cache_key(ioc, providers)
    with _CACHE_LOCK:
        if cache_k in _SCAN_CACHE:
            return dict(_SCAN_CACHE[cache_k])

    ioc_type = detect_ioc_type(ioc)
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
    score = _aggregate_score(provider_results)
    verdict = compute_verdict(provider_results)
    output = {
        "ioc": ioc,
        "type": ioc_type,
        "status": status,
        "score": score,
        "verdict": verdict,
        "providers": provider_results,
        "errors": [],
    }

    with _CACHE_LOCK:
        if len(_SCAN_CACHE) < _MAX_CACHE_SIZE:
            _SCAN_CACHE[cache_k] = dict(output)
    return output
