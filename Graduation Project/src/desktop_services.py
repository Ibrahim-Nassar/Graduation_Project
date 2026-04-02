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

    return {
        "ioc": ioc,
        "type": forced_type,
        "status": ioc_module._aggregate_status(provider_results),  # type: ignore[attr-defined]
        "score": ioc_module._aggregate_score(provider_results),  # type: ignore[attr-defined]
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

        rows.append(
            {
                "ioc": ioc,
                "detected_type": detected_type,
                "effective_type": str(scan_result.get("type", "unknown")),
                "status": str(scan_result.get("status", "unknown")),
                "score": int(scan_result.get("score", 0) or 0),
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
        return {"ok": True, "summary": summary, "result": dump}
    except ValidationError as exc:
        return {
            "ok": False,
            "error": "No ATT&CK mapping could be produced for this log.",
            "details": exc.errors(),
        }
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
    for key, value in summary.items():
        rows.append({"section": "summary", "item": key, "value": str(value)})

    result = payload.get("result", {})
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


def sanitize_api_keys(api_keys: dict[str, str]) -> dict[str, str]:
    return {provider: value.strip() for provider, value in api_keys.items() if provider in PROVIDER_ORDER}


def split_bulk_ioc_text(text: str) -> list[str]:
    return _unique_values([item for item in re.split(r"[\n\r]+", text) if item.strip()])
