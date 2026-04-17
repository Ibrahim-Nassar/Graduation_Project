from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from src.model import load_model
from src.pipeline import run
import src.pipeline as pipeline_module

PROVIDER_ORDER = ("virustotal", "abuseipdb", "otx", "threatfox")
SUPPORTED_MANUAL_TYPES = {"ip", "domain", "url", "hash"}
_SETTINGS_FILE = Path.home() / ".soc_workstation_settings.json"


@dataclass
class SessionSettings:
    api_keys: dict[str, str] = field(default_factory=dict)
    providers: dict[str, bool] = field(default_factory=dict)
    history_enabled: bool = False


def default_session_settings() -> SessionSettings:
    return SessionSettings(
        api_keys={provider: "" for provider in PROVIDER_ORDER},
        providers={provider: True for provider in PROVIDER_ORDER},
        history_enabled=False,
    )


def load_persisted_settings() -> SessionSettings:
    settings = default_session_settings()
    if not _SETTINGS_FILE.exists():
        return settings
    try:
        payload = json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return settings
    if not isinstance(payload, dict):
        return settings

    raw_keys = payload.get("api_keys", {})
    if isinstance(raw_keys, dict):
        cleaned = sanitize_api_keys({str(k): str(v) for k, v in raw_keys.items()})
        settings.api_keys.update(cleaned)

    raw_providers = payload.get("providers", {})
    if isinstance(raw_providers, dict):
        settings.providers.update(
            {name: bool(raw_providers.get(name, True)) for name in PROVIDER_ORDER}
        )

    settings.history_enabled = bool(payload.get("history_enabled", False))
    return settings


def save_persisted_settings(settings: SessionSettings) -> bool:
    payload = {
        "api_keys": {
            provider: sanitize_api_keys(settings.api_keys).get(provider, "")
            for provider in PROVIDER_ORDER
        },
        "providers": {
            provider: bool(settings.providers.get(provider, True))
            for provider in PROVIDER_ORDER
        },
        "history_enabled": bool(settings.history_enabled),
    }
    try:
        _SETTINGS_FILE.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return True
    except OSError:
        return False


def _unique_values(items: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for item in items:
        value = item.strip()
        if not value:
            continue
        normalized = value.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(value)
    return ordered


def _parse_csv_iocs(content: str) -> list[str]:
    rows: list[str] = []
    reader = csv.DictReader(content.splitlines())
    if reader.fieldnames:
        preferred = {"ioc", "indicator", "value", "ioc_value", "indicator_value"}
        field_map = {field.lower().strip(): field for field in reader.fieldnames if field}
        selected_column = next((field_map[name] for name in preferred if name in field_map), None)
        for row in reader:
            if selected_column and row.get(selected_column):
                rows.append(str(row.get(selected_column, "")).strip())
                continue
            for raw_value in row.values():
                if raw_value and str(raw_value).strip():
                    rows.append(str(raw_value).strip())
                    break
        return rows

    first_column_reader = csv.reader(content.splitlines())
    for row in first_column_reader:
        if row and row[0].strip():
            rows.append(row[0].strip())
    return rows


def _parse_text_iocs(content: str) -> list[str]:
    values: list[str] = []
    for line in content.splitlines():
        pieces = [line] if "," not in line else line.split(",")
        for piece in pieces:
            value = piece.strip()
            if value:
                values.append(value)
    return values


def load_iocs_from_file(file_path: str | None) -> list[str]:
    if not file_path:
        return []
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".csv":
        return _unique_values(_parse_csv_iocs(content))
    return _unique_values(_parse_text_iocs(content))


def collect_iocs(single_ioc: str = "", bulk_text: str = "", file_path: str | None = None) -> list[str]:
    values: list[str] = []
    if single_ioc.strip():
        values.append(single_ioc.strip())
    if bulk_text.strip():
        values.extend(_parse_text_iocs(bulk_text))
    values.extend(load_iocs_from_file(file_path))
    return _unique_values(values)


def _provider_payload(
    ioc_module: Any,
    provider_name: str,
    ioc: str,
    ioc_type: str,
    providers: dict[str, bool],
    api_keys: dict[str, str],
) -> dict[str, Any] | None:
    if provider_name == "virustotal" and providers.get("virustotal"):
        return ioc_module._normalize_provider_result(  # type: ignore[attr-defined]
            "virustotal",
            ioc_module.vt_lookup(ioc, ioc_type, api_keys.get("virustotal")),
            ioc,
            ioc_type,
        )
    if provider_name == "abuseipdb" and providers.get("abuseipdb") and ioc_type == ioc_module.IOC_TYPE_IP:
        return ioc_module._normalize_provider_result(  # type: ignore[attr-defined]
            "abuseipdb",
            ioc_module.abuseipdb_lookup(ioc, api_keys.get("abuseipdb")),
            ioc,
            ioc_type,
        )
    if provider_name == "otx" and providers.get("otx"):
        return ioc_module._normalize_provider_result(  # type: ignore[attr-defined]
            "otx",
            ioc_module.otx_lookup(ioc, ioc_type, api_keys.get("otx")),
            ioc,
            ioc_type,
        )
    if provider_name == "threatfox" and providers.get("threatfox"):
        return ioc_module._normalize_provider_result(  # type: ignore[attr-defined]
            "threatfox",
            ioc_module.threatfox_lookup(ioc, ioc_type, api_keys.get("threatfox")),
            ioc,
            ioc_type,
        )
    return None


def _supports_forced_ioc_type(ioc_module: Any) -> bool:
    required_attrs = {
        "_enabled_providers",
        "_normalize_provider_result",
        "_aggregate_status",
        "_aggregate_score",
        "vt_lookup",
        "abuseipdb_lookup",
        "otx_lookup",
        "threatfox_lookup",
        "IOC_TYPE_IP",
    }
    return all(hasattr(ioc_module, attr) for attr in required_attrs)


def _scan_with_forced_type(
    ioc_module: Any,
    ioc: str,
    forced_type: str,
    providers: dict[str, bool] | None,
    api_keys: dict[str, str] | None,
) -> dict[str, Any]:
    enabled = ioc_module._enabled_providers(providers)  # type: ignore[attr-defined]
    keys = api_keys or {}
    provider_results: dict[str, dict[str, Any]] = {}

    for provider_name in PROVIDER_ORDER:
        payload = _provider_payload(ioc_module, provider_name, ioc, forced_type, enabled, keys)
        if payload is not None:
            provider_results[provider_name] = payload

    verdict: dict[str, Any] = {}
    if hasattr(ioc_module, "compute_verdict"):
        verdict = ioc_module.compute_verdict(provider_results)

    return {
        "ioc": ioc,
        "type": forced_type,
        "status": ioc_module._aggregate_status(provider_results),  # type: ignore[attr-defined]
        "score": ioc_module._aggregate_score(provider_results),  # type: ignore[attr-defined]
        "verdict": verdict,
        "providers": provider_results,
    }


def _load_ioc_module() -> Any | None:
    return pipeline_module._load_ioc_enrichment_module()


def _flatten_provider_statuses(provider_results: dict[str, Any]) -> dict[str, str]:
    return {
        provider_name: str((provider_results.get(provider_name) or {}).get("status", "n/a"))
        for provider_name in PROVIDER_ORDER
    }


def scan_iocs(
    iocs: list[str],
    *,
    manual_ioc_type: str | None,
    providers: dict[str, bool] | None,
    api_keys: dict[str, str] | None,
) -> list[dict[str, Any]]:
    ioc_module = _load_ioc_module()
    rows: list[dict[str, Any]] = []

    for value in iocs:
        ioc = value.strip()
        if not ioc:
            continue

        if ioc_module is None or not hasattr(ioc_module, "scan_ioc"):
            detected_type = "unknown"
            scan_result = {
                "ioc": ioc,
                "type": "unknown",
                "status": "error",
                "score": 0,
                "providers": {},
                "errors": ["IOC enrichment module unavailable"],
            }
        else:
            detected_type = str(ioc_module.detect_ioc_type(ioc))
            forced_type = (manual_ioc_type or "").strip().lower()
            if forced_type in SUPPORTED_MANUAL_TYPES and _supports_forced_ioc_type(ioc_module):
                scan_result = _scan_with_forced_type(ioc_module, ioc, forced_type, providers, api_keys)
            else:
                scan_result = ioc_module.scan_ioc(ioc, providers=providers, api_keys=api_keys)

        provider_results = scan_result.get("providers", {})
        provider_statuses = _flatten_provider_statuses(
            provider_results if isinstance(provider_results, dict) else {}
        )
        effective_type = str(scan_result.get("type", "unknown"))
        if effective_type != "ip" and (providers or {}).get("abuseipdb", True):
            provider_statuses["abuseipdb"] = "not_supported"
        provider_summary = ", ".join(
            f"{provider}:{status}" for provider, status in provider_statuses.items()
        )

        errors = []
        if isinstance(scan_result.get("errors"), list):
            errors.extend(str(item) for item in scan_result.get("errors", []))
        if isinstance(provider_results, dict):
            for provider_name in PROVIDER_ORDER:
                payload = provider_results.get(provider_name)
                if isinstance(payload, dict) and payload.get("error"):
                    errors.append(f"{provider_name}: {payload.get('error')}")

        verdict_data = scan_result.get("verdict", {})
        if not isinstance(verdict_data, dict):
            verdict_data = {}

        rows.append(
            {
                "ioc": ioc,
                "detected_type": detected_type,
                "effective_type": effective_type,
                "status": str(scan_result.get("status", "unknown")),
                "score": int(scan_result.get("score", 0) or 0),
                "verdict": str(verdict_data.get("verdict", "Unknown")),
                "verdict_confidence": int(verdict_data.get("confidence", 0) or 0),
                "verdict_reasoning": str(verdict_data.get("reasoning", "")),
                "virustotal": provider_statuses["virustotal"],
                "abuseipdb": provider_statuses["abuseipdb"],
                "otx": provider_statuses["otx"],
                "threatfox": provider_statuses["threatfox"],
                "provider_summary": provider_summary,
                "error_count": len(errors),
                "errors": errors,
                "raw": scan_result,
            }
        )

    return rows


def summarize_ioc_rows(rows: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"total": 0, "malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0, "error_rows": 0}
    for row in rows:
        summary["total"] += 1
        status = str(row.get("status", "unknown")).lower()
        if status in {"malicious", "suspicious", "clean", "unknown"}:
            summary[status] += 1
        else:
            summary["unknown"] += 1
        if int(row.get("error_count", 0) or 0) > 0:
            summary["error_rows"] += 1
    return summary


def _read_log_file_content(file_path: str) -> str:
    path = Path(file_path)
    content = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(content)
            if isinstance(payload, dict) and isinstance(payload.get("raw_log"), str):
                return payload["raw_log"]
        except json.JSONDecodeError:
            pass
    return content


def analyze_soc_log(
    raw_log: str,
    *,
    model_path: str = "",
    enrich_iocs: bool = False,
    ioc_providers: dict[str, bool] | None = None,
    ioc_api_keys: dict[str, str] | None = None,
) -> dict[str, Any]:
    value = raw_log.strip()
    if not value:
        return {"ok": False, "error": "No log content provided."}

    try:
        model = load_model(model_path.strip()) if model_path.strip() else None
        result = run(
            value,
            model=model,
            enrich_iocs=enrich_iocs,
            ioc_providers=ioc_providers,
            ioc_api_keys=ioc_api_keys,
        )
        dump = result.model_dump(mode="json")
        top_mapping = dump["attack_mapping"][0]
        summary = {
            "technique_id": top_mapping["technique_id"],
            "technique_name": top_mapping["technique_name"],
            "confidence": top_mapping["confidence"],
            "mapping_source": dump["audit"].get("mapping_source"),
            "entity_count": len(dump["entities"]),
        }
        out: dict[str, Any] = {"ok": True, "summary": summary, "result": dump}
        out["analyst_brief"] = generate_analyst_brief(out)
        out["investigation_summary"] = generate_investigation_summary(out)

        entity_values = [str(e.get("value", "")) for e in dump.get("entities", []) if e.get("type") in {"ipv4", "domain"}]
        for ev in entity_values:
            correlation_store.record_ioc(ev, "seen", "soc_analysis")
        correlation_store.record_technique(
            top_mapping["technique_id"], top_mapping["technique_name"],
            entity_values, top_mapping["confidence"],
        )
        out["correlation_insights"] = correlation_store.get_all_insights(entity_values, top_mapping["technique_id"])
        return out
    except ValidationError as exc:
        partial_result: dict[str, Any] = {}
        try:
            event = pipeline_module._normalize_event(value)
            entities = pipeline_module._extract_entities(event.raw_event, event.normalized_event)
            audit: dict[str, Any] = {
                "mapping_source": "none",
                "normalized_event": event.normalized_event,
                "entity_count": len(entities),
                "mapping_count": 0,
            }
            if enrich_iocs:
                audit["ioc_enrichment"] = pipeline_module._enrich_iocs(
                    entities,
                    providers=ioc_providers,
                    api_keys=ioc_api_keys,
                )
            partial_result = {
                "entities": [entity.model_dump(mode="json") for entity in entities],
                "attack_mapping": [],
                "epc": {},
                "audit": audit,
            }
        except Exception:
            partial_result = {}
        summary = {
            "technique_id": "N/A",
            "technique_name": "Not mapped",
            "confidence": 0.0,
            "mapping_source": "none",
            "entity_count": int(partial_result.get("audit", {}).get("entity_count", 0) or 0)
            if isinstance(partial_result, dict)
            else 0,
        }
        out: dict[str, Any] = {
            "ok": False,
            "summary": summary,
            "result": partial_result,
            "error": "No ATT&CK mapping could be produced for this log.",
            "reason": "no_mapping",
            "partial_result": partial_result,
            "details": exc.errors(),
        }
        out["analyst_brief"] = generate_analyst_brief(out)
        out["investigation_summary"] = generate_investigation_summary(out)

        entity_values = [
            str(e.get("value", ""))
            for e in (partial_result.get("entities", []) if isinstance(partial_result, dict) else [])
            if e.get("type") in {"ipv4", "domain"}
        ]
        for ev in entity_values:
            correlation_store.record_ioc(ev, "seen", "soc_analysis")
        out["correlation_insights"] = correlation_store.get_ioc_insights(entity_values)
        return out
    except Exception as exc:  # pragma: no cover - UI safety net
        return {"ok": False, "error": str(exc)}


def load_soc_log_inputs(raw_text: str, file_path: str | None) -> str:
    if file_path:
        return _read_log_file_content(file_path).strip()
    return raw_text.strip()


def export_json(path: str, payload: Any) -> None:
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def export_ioc_csv(path: str, rows: list[dict[str, Any]]) -> None:
    columns = [
        "ioc",
        "verdict",
        "verdict_confidence",
        "verdict_reasoning",
        "detected_type",
        "effective_type",
        "status",
        "score",
        "virustotal",
        "abuseipdb",
        "otx",
        "threatfox",
        "provider_summary",
        "error_count",
        "errors",
    ]
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            output = dict(row)
            output["errors"] = " | ".join(str(item) for item in row.get("errors", []))
            writer.writerow({name: output.get(name, "") for name in columns})


def export_soc_csv(path: str, payload: dict[str, Any]) -> None:
    rows: list[dict[str, str]] = []
    summary = payload.get("summary", {})
    result = payload.get("result", {})
    if not isinstance(result, dict):
        result = {}
    if not result and isinstance(payload.get("partial_result"), dict):
        result = payload.get("partial_result", {})

    if not summary and isinstance(result, dict):
        audit = result.get("audit", {}) if isinstance(result.get("audit"), dict) else {}
        summary = {
            "technique_id": "N/A",
            "technique_name": "Not mapped",
            "confidence": 0.0,
            "mapping_source": str(audit.get("mapping_source", "none")),
            "entity_count": int(audit.get("entity_count", len(result.get("entities", []) or [])) or 0),
        }
    analyst_brief = str(payload.get("analyst_brief", "")).strip()
    if analyst_brief:
        rows.append({"section": "analyst_brief", "item": "brief", "value": analyst_brief})

    for key, value in summary.items():
        rows.append({"section": "summary", "item": key, "value": str(value)})

    for index, entity in enumerate(result.get("entities", []), start=1):
        rows.append({"section": "entity", "item": f"{index}:{entity.get('type', 'unknown')}", "value": str(entity.get("value", ""))})

    for index, mapping in enumerate(result.get("attack_mapping", []), start=1):
        rows.append(
            {
                "section": "mitre",
                "item": f"{index}:{mapping.get('technique_id', '')}",
                "value": str(mapping.get("rationale", "")),
            }
        )

    epc = result.get("epc", {})
    rows.append({"section": "epc", "item": "explain", "value": str(epc.get("explain", ""))})
    rows.append(
        {"section": "epc", "item": "plan", "value": " | ".join(str(item) for item in epc.get("plan", []))}
    )
    rows.append(
        {
            "section": "epc",
            "item": "checklist",
            "value": " | ".join(str(item) for item in epc.get("checklist", [])),
        }
    )

    enrichment = result.get("audit", {}).get("ioc_enrichment", [])
    for index, item in enumerate(enrichment, start=1):
        rows.append(
            {
                "section": "ioc_enrichment",
                "item": f"{index}:{item.get('ioc', '')}",
                "value": str(item.get("status", "unknown")),
            }
        )

    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["section", "item", "value"])
        writer.writeheader()
        writer.writerows(rows)


def generate_analyst_brief(payload: dict[str, Any]) -> str:
    """Build a deterministic, template-based analyst brief from SOC analysis results.

    Returns a compact 2-4 sentence narrative suitable for display at the top
    of the SOC results area.  No LLM is used; all text is derived from
    structured fields already present in the payload.
    """
    summary = payload.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    result = payload.get("result", {})
    if not isinstance(result, dict):
        result = {}
    if not result and isinstance(payload.get("partial_result"), dict):
        result = payload.get("partial_result", {})

    technique_id = str(summary.get("technique_id", "N/A"))
    technique_name = str(summary.get("technique_name", "N/A"))
    mapping_source = str(summary.get("mapping_source", "none"))
    confidence = float(summary.get("confidence", 0.0) or 0.0)
    entity_count = int(summary.get("entity_count", 0) or 0)

    entities = result.get("entities", []) if isinstance(result.get("entities"), list) else []
    mappings = result.get("attack_mapping", []) if isinstance(result.get("attack_mapping"), list) else []
    epc = result.get("epc", {}) if isinstance(result.get("epc"), dict) else {}

    entity_labels = []
    for entity in entities[:5]:
        etype = str(entity.get("type", "")).strip()
        evalue = str(entity.get("value", "")).strip()
        if etype and evalue:
            entity_labels.append(f"{etype} \u2018{evalue}\u2019")
    entity_mention = ", ".join(entity_labels) if entity_labels else None

    if technique_id == "N/A" or not mappings:
        parts = ["Analysis completed but no MITRE ATT&CK mapping was produced for this log."]
        if entity_mention:
            parts.append(f"Extracted entities: {entity_mention}.")
        elif entity_count > 0:
            parts.append(f"{entity_count} entities were extracted but no technique pattern matched.")
        else:
            parts.append("No entities could be extracted from the input.")
        parts.append(
            "Recommended action: review extracted fields for missing context,"
            " add correlated log lines, and re-analyze."
        )
        return " ".join(parts)

    primary = mappings[0]
    rationale = str(primary.get("rationale", "")).strip()
    evidence_refs = primary.get("evidence_refs", []) if isinstance(primary.get("evidence_refs"), list) else []
    evidence_summary = ", ".join(str(e) for e in evidence_refs[:3]) if evidence_refs else ""

    parts: list[str] = []
    if entity_mention:
        parts.append(f"Log analysis identified activity involving {entity_mention}.")
    else:
        parts.append("Log analysis identified suspicious activity.")

    source_qualifier = ""
    if mapping_source == "ml_fallback":
        source_qualifier = " (ML fallback \u2014 analyst review required)"
    elif confidence < 0.6:
        source_qualifier = " (low confidence \u2014 verify before action)"
    parts.append(
        f"Mapped to {technique_id} ({technique_name})"
        f" at {confidence:.0%} confidence{source_qualifier}."
    )

    if rationale:
        parts.append(f"Primary evidence: {rationale}")
    elif evidence_summary:
        parts.append(f"Key signals: {evidence_summary}.")

    plan = epc.get("plan", []) if isinstance(epc.get("plan"), list) else []
    if plan and str(plan[0]).strip():
        parts.append(f"Recommended first action: {plan[0]}")

    return " ".join(parts)


def sanitize_api_keys(api_keys: dict[str, str]) -> dict[str, str]:
    return {provider: value.strip() for provider, value in api_keys.items() if provider in PROVIDER_ORDER}


def split_bulk_ioc_text(text: str) -> list[str]:
    return _unique_values([item for item in re.split(r"[\n\r]+", text) if item.strip()])


# ── Correlation Engine ────────────────────────────────────────────────────────

_MULTI_STAGE_PATTERNS: list[tuple[frozenset[str], str]] = [
    (frozenset({"T1003", "T1021"}), "Credential theft followed by lateral movement — possible compromised-account pivot"),
    (frozenset({"T1059", "T1003"}), "Script execution with credential dumping — possible post-exploitation"),
    (frozenset({"T1110", "T1021"}), "Brute-force attempt followed by remote service access — may indicate successful breach"),
    (frozenset({"T1059", "T1071"}), "Script execution with C2-style DNS activity — possible malware beaconing"),
    (frozenset({"T1053", "T1059"}), "Scheduled task with scripting — possible persistence mechanism"),
    (frozenset({"T1070", "T1003"}), "Log clearing after credential access — likely evidence destruction"),
]


class CorrelationStore:
    """In-memory store that tracks IOCs and techniques across analyses."""

    def __init__(self) -> None:
        self._ioc_sightings: dict[str, list[dict[str, Any]]] = {}
        self._technique_history: list[dict[str, Any]] = []

    def record_ioc(self, ioc: str, status: str, context: str = "") -> None:
        key = ioc.strip().lower()
        if key not in self._ioc_sightings:
            self._ioc_sightings[key] = []
        self._ioc_sightings[key].append({
            "status": status,
            "context": context,
            "timestamp": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    def record_technique(self, technique_id: str, technique_name: str, entities: list[str], confidence: float) -> None:
        self._technique_history.append({
            "technique_id": technique_id,
            "technique_name": technique_name,
            "entities": entities,
            "confidence": confidence,
            "timestamp": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    def get_ioc_insights(self, iocs: list[str]) -> list[dict[str, str]]:
        insights: list[dict[str, str]] = []
        for ioc in iocs:
            key = ioc.strip().lower()
            sightings = self._ioc_sightings.get(key, [])
            if len(sightings) > 1:
                mal_count = sum(1 for s in sightings if s["status"] == "malicious")
                insights.append({
                    "type": "repeated_ioc",
                    "indicator": ioc,
                    "summary": f"IOC '{ioc}' seen {len(sightings)} times across analyses"
                               + (f" ({mal_count} malicious)" if mal_count else ""),
                })
        return insights

    def get_technique_insights(self, current_technique: str) -> list[dict[str, str]]:
        insights: list[dict[str, str]] = []
        past_techniques = {entry["technique_id"] for entry in self._technique_history}
        if current_technique in past_techniques:
            count = sum(1 for e in self._technique_history if e["technique_id"] == current_technique)
            insights.append({
                "type": "repeated_technique",
                "indicator": current_technique,
                "summary": f"Technique {current_technique} observed {count + 1} times across analyses",
            })

        all_techniques = past_techniques | {current_technique}
        for pattern_set, description in _MULTI_STAGE_PATTERNS:
            if pattern_set.issubset(all_techniques):
                techniques_str = " + ".join(sorted(pattern_set))
                insights.append({
                    "type": "multi_stage",
                    "indicator": techniques_str,
                    "summary": description,
                })
        return insights

    def get_all_insights(self, iocs: list[str], current_technique: str) -> list[dict[str, str]]:
        return self.get_ioc_insights(iocs) + self.get_technique_insights(current_technique)

    def clear(self) -> None:
        self._ioc_sightings.clear()
        self._technique_history.clear()


correlation_store = CorrelationStore()


# ── Smart Summary Generator ──────────────────────────────────────────────────

_TECHNIQUE_DESCRIPTIONS: dict[str, str] = {
    "T1003": "credential harvesting from memory or disk",
    "T1021": "lateral movement using remote services",
    "T1053": "persistence via scheduled task or job",
    "T1055": "code injection into a running process",
    "T1059": "execution through a command-line interpreter or scripting engine",
    "T1070": "tampering with logs or forensic artifacts",
    "T1071": "command-and-control communication over application-layer protocols",
    "T1110": "brute-force password guessing against authentication services",
}

_SEVERITY_ACTIONS: dict[str, str] = {
    "critical": "Immediately isolate affected hosts and escalate to incident response.",
    "high": "Prioritize investigation and contain affected systems within the hour.",
    "medium": "Investigate within the shift and apply targeted mitigations.",
    "low": "Schedule review and monitor for recurrence.",
    "info": "No immediate action required — archive for awareness.",
}


def generate_investigation_summary(payload: dict[str, Any]) -> dict[str, str]:
    """Generate a structured investigation summary from SOC analysis results.

    Returns a dict with ``what_happened``, ``severity_assessment``, and ``next_steps``.
    """
    summary = payload.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    result = payload.get("result", {})
    if not isinstance(result, dict):
        result = {}
    if not result and isinstance(payload.get("partial_result"), dict):
        result = payload.get("partial_result", {})

    technique_id = str(summary.get("technique_id", "N/A"))
    technique_name = str(summary.get("technique_name", "N/A"))
    confidence = float(summary.get("confidence", 0.0) or 0.0)
    entity_count = int(summary.get("entity_count", 0) or 0)
    mapping_source = str(summary.get("mapping_source", "none"))

    entities = result.get("entities", []) if isinstance(result.get("entities"), list) else []
    epc = result.get("epc", {}) if isinstance(result.get("epc"), dict) else {}

    severity = assess_severity(payload)

    entity_subjects = []
    for e in entities[:4]:
        etype = str(e.get("type", "")).strip()
        evalue = str(e.get("value", "")).strip()
        if etype and evalue:
            entity_subjects.append(f"{etype} '{evalue}'")

    if technique_id == "N/A":
        what = "Analysis did not identify a known attack pattern."
        if entity_subjects:
            what += f" Entities observed: {', '.join(entity_subjects)}."
        elif entity_count > 0:
            what += f" {entity_count} entities were extracted but matched no technique."
        else:
            what += " No extractable indicators were found in the log."
    else:
        description = _TECHNIQUE_DESCRIPTIONS.get(technique_id, technique_name.lower())
        what = f"The log indicates {description}"
        if mapping_source == "ml_fallback":
            what += " (identified via ML model — manual verification recommended)"
        what += f", mapped to {technique_id} ({technique_name}) at {confidence:.0%} confidence."
        if entity_subjects:
            what += f" Involved entities: {', '.join(entity_subjects)}."

    sev_text = f"Severity: {severity.upper()}."
    if confidence < 0.6 and technique_id != "N/A":
        sev_text += " Note: confidence is below 60% — treat as preliminary."

    action = _SEVERITY_ACTIONS.get(severity, "Monitor and document findings.")
    plan_items = epc.get("plan", []) if isinstance(epc.get("plan"), list) else []
    if plan_items:
        action += " Specifically: " + plan_items[0]

    return {
        "what_happened": what,
        "severity_assessment": sev_text,
        "next_steps": action,
    }


_HIGH_SEVERITY_TECHNIQUES = frozenset({"T1003", "T1055"})
_MEDIUM_SEVERITY_TECHNIQUES = frozenset({"T1059", "T1070", "T1110", "T1053", "T1071"})


def assess_severity(payload: dict[str, Any]) -> str:
    """Derive a severity level from SOC analysis results."""
    summary = payload.get("summary", {})
    if not isinstance(summary, dict):
        return "info"
    confidence = float(summary.get("confidence", 0) or 0)
    technique_id = str(summary.get("technique_id", "N/A"))
    if technique_id == "N/A":
        return "info"
    if technique_id in _HIGH_SEVERITY_TECHNIQUES and confidence >= 0.7:
        return "critical"
    if technique_id in _HIGH_SEVERITY_TECHNIQUES:
        return "high"
    if technique_id in _MEDIUM_SEVERITY_TECHNIQUES and confidence >= 0.8:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"
