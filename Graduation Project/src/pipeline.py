from __future__ import annotations

import importlib
import os
import re
from collections import defaultdict
from pathlib import Path
import sys
from typing import Any

from src.contracts import AttackMapping, EPC, Entity, Event, Result
from src.model import predict_attack

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
USERNAME_RE = re.compile(
    r"(?i)\b(?:username|user|account|login)\s*(?:=|:)\s*([a-zA-Z0-9._\\-]{2,})\b"
)
PROCESS_RE = re.compile(r"\b([a-zA-Z0-9_.-]+\.exe)\b", re.IGNORECASE)
FAILED_LOGIN_RE = re.compile(
    r"(?i)(?:failed\s+(?:login|logon|authentication)|login\s+failed|invalid\s+password)"
)
KV_VALUE_RE = r"(?:\"([^\"]+)\"|'([^']+)'|([^\s,;]+))"
TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)
IOC_ENTITY_TO_SCAN_TYPE = {
    "ipv4": "ip",
    "domain": "domain",
}
_IOC_MODULE_CACHE: Any | None = None


def _extract_first_kv_value(raw_log: str, keys: tuple[str, ...]) -> str | None:
    keys_pattern = "|".join(re.escape(key) for key in keys)
    pattern = re.compile(rf"(?i)\b(?:{keys_pattern})\s*(?:=|:)\s*{KV_VALUE_RE}")
    match = pattern.search(raw_log)
    if not match:
        return None
    for group in match.groups():
        if group is not None and group != "":
            return group
    return None


def _extract_timestamp(raw_log: str) -> str | None:
    timestamp = _extract_first_kv_value(raw_log, ("timestamp", "time", "ts"))
    if timestamp:
        return timestamp
    direct_match = TIMESTAMP_RE.search(raw_log)
    if direct_match:
        return direct_match.group(0)
    return None


def _extract_domain_value(raw_log: str) -> str | None:
    domain = _extract_first_kv_value(raw_log, ("domain", "qname", "destination", "target"))
    if domain and DOMAIN_RE.fullmatch(domain):
        return domain
    match = DOMAIN_RE.search(raw_log)
    if match:
        return match.group(0)
    return None


def _extract_process_value(raw_log: str) -> str | None:
    process = _extract_first_kv_value(raw_log, ("process", "proc", "image"))
    if process:
        return process
    match = PROCESS_RE.search(raw_log)
    if match:
        return match.group(1)
    if re.search(r"(?i)\bpowershell\b", raw_log):
        return "powershell"
    return None


def _normalize_event(raw_log: str) -> Event:
    normalized_event: dict[str, Any] = {}
    timestamp = _extract_timestamp(raw_log)
    username = _extract_first_kv_value(raw_log, ("username", "user", "account", "login"))
    hostname = _extract_first_kv_value(raw_log, ("host", "hostname", "computer"))
    process = _extract_process_value(raw_log)
    command_line = _extract_first_kv_value(raw_log, ("cmdline", "command_line", "command", "cmd"))
    source_ip = _extract_first_kv_value(raw_log, ("src_ip", "source_ip", "src"))
    destination_ip = _extract_first_kv_value(raw_log, ("dst_ip", "destination_ip", "dest_ip", "dst"))
    domain = _extract_domain_value(raw_log)

    extracted_fields: dict[str, str | None] = {
        "timestamp": timestamp,
        "username": username,
        "hostname": hostname,
        "process": process,
        "command_line": command_line,
        "source_ip": source_ip if source_ip and IPV4_RE.fullmatch(source_ip) else None,
        "destination_ip": destination_ip
        if destination_ip and IPV4_RE.fullmatch(destination_ip)
        else None,
        "domain": domain,
    }

    for key, value in extracted_fields.items():
        if value is not None:
            normalized_event[key] = value

    return Event(raw_event=raw_log, normalized_event=normalized_event)


def _append_entity(entities: list[Entity], seen: set[tuple[str, str]], entity: Entity) -> None:
    key = (entity.type, entity.value.lower())
    if key in seen:
        return
    seen.add(key)
    entities.append(entity)


def _build_entity(
    entity_type: str,
    value: str,
    raw_log: str,
    *,
    case_insensitive: bool = False,
) -> Entity:
    flags = re.IGNORECASE if case_insensitive else 0
    match = re.search(re.escape(value), raw_log, flags)
    if match:
        return Entity(
            type=entity_type,
            value=match.group(0),
            start=match.start(),
            end=match.end(),
            evidence_ref=match.group(0),
        )
    return Entity(type=entity_type, value=value, evidence_ref=value)


def _extract_entities(raw_log: str, normalized_event: dict[str, Any]) -> list[Entity]:
    entities: list[Entity] = []
    seen: set[tuple[str, str]] = set()

    normalized_to_entity_types: tuple[tuple[str, str], ...] = (
        ("username", "username"),
        ("hostname", "hostname"),
        ("process", "process"),
        ("source_ip", "ipv4"),
        ("destination_ip", "ipv4"),
        ("domain", "domain"),
    )
    for field_name, entity_type in normalized_to_entity_types:
        value = normalized_event.get(field_name)
        if isinstance(value, str) and value:
            _append_entity(entities, seen, _build_entity(entity_type, value, raw_log))

    for match in IPV4_RE.finditer(raw_log):
        _append_entity(
            entities,
            seen,
            Entity(
                type="ipv4",
                value=match.group(0),
                start=match.start(),
                end=match.end(),
                evidence_ref=match.group(0),
            ),
        )

    for match in DOMAIN_RE.finditer(raw_log):
        _append_entity(
            entities,
            seen,
            Entity(
                type="domain",
                value=match.group(0),
                start=match.start(),
                end=match.end(),
                evidence_ref=match.group(0),
            ),
        )

    for match in USERNAME_RE.finditer(raw_log):
        username = match.group(1)
        _append_entity(
            entities,
            seen,
            Entity(
                type="username",
                value=username,
                start=match.start(1),
                end=match.end(1),
                evidence_ref=username,
            ),
        )

    process_found = any(entity.type == "process" for entity in entities)
    for match in PROCESS_RE.finditer(raw_log):
        process_found = True
        process_name = match.group(1)
        _append_entity(
            entities,
            seen,
            Entity(
                type="process",
                value=process_name,
                start=match.start(1),
                end=match.end(1),
                evidence_ref=process_name,
            ),
        )

    if not process_found and re.search(r"(?i)\bpowershell\b", raw_log):
        powershell_match = re.search(r"(?i)\bpowershell\b", raw_log)
        assert powershell_match is not None
        _append_entity(
            entities,
            seen,
            Entity(
                type="process",
                value="powershell",
                start=powershell_match.start(),
                end=powershell_match.end(),
                evidence_ref=powershell_match.group(0),
            ),
        )

    return entities


def _is_random_subdomain(label: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9]{8,}", label.lower()))


def _detect_dns_tunnel(domains: list[str], raw_log: str) -> bool:
    if "dns" not in raw_log.lower():
        return False
    if len(domains) < 4:
        return False

    grouped: dict[str, set[str]] = defaultdict(set)
    for domain in domains:
        parts = domain.lower().split(".")
        if len(parts) < 3:
            continue
        # Treat leftmost label as candidate data chunk and rest as root domain.
        root = ".".join(parts[1:])
        label = parts[0]
        if _is_random_subdomain(label):
            grouped[root].add(label)

    return any(len(labels) >= 3 for labels in grouped.values())


def _build_attack_mappings(
    raw_log: str, domains: list[str], normalized_event: dict[str, Any]
) -> list[AttackMapping]:
    mappings: list[AttackMapping] = []
    lowered = raw_log.lower()
    normalized_process = str(normalized_event.get("process", "")).lower()
    normalized_command = str(normalized_event.get("command_line", "")).lower()
    has_powershell = "powershell" in lowered or "powershell" in normalized_process
    has_encoded_switch = "-enc" in lowered or "-enc" in normalized_command

    if has_powershell and has_encoded_switch:
        powershell_match = re.search(r"(?i)\bpowershell\b", raw_log)
        enc_switch_match = re.search(r"(?i)-enc(?:odedcommand)?\b", raw_log)
        if powershell_match and enc_switch_match:
            evidence_refs = [powershell_match.group(0), enc_switch_match.group(0)]
        else:
            evidence_refs = [raw_log[:80] or "raw_log"]
        mappings.append(
            AttackMapping(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                confidence=0.9,
                rationale="PowerShell executed with encoded command switch.",
                evidence_refs=evidence_refs,
            )
        )

    if _detect_dns_tunnel(domains, raw_log):
        evidence = [domain for domain in domains if len(domain.split(".")) >= 3][:3]
        mappings.append(
            AttackMapping(
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                confidence=0.85,
                rationale="Repeated DNS lookups to randomized subdomains indicate tunneling behavior.",
                evidence_refs=evidence or [domains[0]],
            )
        )

    failed_login_matches = list(FAILED_LOGIN_RE.finditer(raw_log))
    failed_attempts = len(failed_login_matches)
    if failed_attempts >= 3:
        evidence_refs = [match.group(0) for match in failed_login_matches[:3]]
        mappings.append(
            AttackMapping(
                technique_id="T1110",
                technique_name="Brute Force",
                confidence=0.88,
                rationale="Multiple failed authentication attempts observed in a short sequence.",
                evidence_refs=evidence_refs,
            )
        )

    return mappings


def _build_epc(primary_mapping: AttackMapping) -> EPC:
    templates: dict[str, dict[str, list[str] | str | float]] = {
        "T1059": {
            "explain": "Encoded PowerShell execution may indicate script-based command execution by an adversary.",
            "plan": [
                "Isolate host and collect full PowerShell command history.",
                "Decode command content and verify whether it is authorized administration activity.",
            ],
            "checklist": [
                "Retrieve parent process and command-line telemetry.",
                "Check user/session context and recent privilege changes.",
            ],
            "confidence": 0.9,
        },
        "T1071": {
            "explain": "High-volume DNS requests to randomized subdomains can indicate C2 or exfiltration tunneling.",
            "plan": [
                "Identify source host and block suspicious domain at DNS controls.",
                "Correlate DNS activity with outbound network sessions and data transfer volume.",
            ],
            "checklist": [
                "Count unique subdomains queried per minute.",
                "Validate whether destination domain is approved or known malicious.",
            ],
            "confidence": 0.85,
        },
        "T1110": {
            "explain": "Repeated failed logins suggest possible brute-force credential guessing.",
            "plan": [
                "Temporarily lock targeted account(s) and enforce password reset.",
                "Trace source IP and apply access controls or rate limiting.",
            ],
            "checklist": [
                "Review authentication logs for successful follow-on login.",
                "Confirm MFA status and policy enforcement for impacted account.",
            ],
            "confidence": 0.88,
        },
    }

    template = templates.get(
        primary_mapping.technique_id,
        {
            "explain": "Suspicious activity requires triage and containment validation.",
            "plan": ["Collect host and network evidence for escalation."],
            "checklist": ["Verify impacted assets.", "Confirm containment status."],
            "confidence": 0.5,
        },
    )

    return EPC(
        explain=str(template["explain"]),
        plan=list(template["plan"]),  # type: ignore[arg-type]
        checklist=list(template["checklist"]),  # type: ignore[arg-type]
        confidence=float(template["confidence"]),
        citations=primary_mapping.evidence_refs,
    )


def _build_ml_fallback_mapping(raw_log: str, model: Any) -> AttackMapping:
    prediction = predict_attack(raw_log, model)
    technique_id = str(prediction["technique_id"])
    technique_name_by_id = {
        "T1059": "Command and Scripting Interpreter",
        "T1071": "Application Layer Protocol",
        "T1110": "Brute Force",
    }
    technique_name = technique_name_by_id.get(technique_id, "Model Predicted Technique")
    return AttackMapping(
        technique_id=technique_id,
        technique_name=technique_name,
        confidence=float(prediction["confidence"]),
        rationale="ML fallback prediction because no deterministic ATT&CK rule matched; analyst review required.",
        evidence_refs=["ml_prediction"],
    )


def _build_ml_fallback_epc(mapping: AttackMapping) -> EPC:
    return EPC(
        explain="Technique is model-predicted fallback output and must be analyst-reviewed before response actions.",
        plan=[
            "Validate prediction against raw log context and related telemetry.",
            "Confirm or correct ATT&CK technique labeling in analyst workflow.",
        ],
        checklist=[
            "Check whether any deterministic rule should have matched this event.",
            "Record analyst validation outcome for future model improvement.",
        ],
        confidence=mapping.confidence,
        citations=mapping.evidence_refs,
    )


def _load_ioc_enrichment_module() -> Any | None:
    global _IOC_MODULE_CACHE
    if _IOC_MODULE_CACHE is not None:
        return _IOC_MODULE_CACHE

    try:
        module = importlib.import_module("ioc_enrichment")
        _IOC_MODULE_CACHE = module
        return module
    except ModuleNotFoundError:
        for ioc_src_path in _ioc_enrichment_search_paths():
            if str(ioc_src_path) not in sys.path:
                sys.path.insert(0, str(ioc_src_path))
            try:
                module = importlib.import_module("ioc_enrichment")
                _IOC_MODULE_CACHE = module
                return module
            except ModuleNotFoundError:
                continue
        _IOC_MODULE_CACHE = None
        return None


def _ioc_enrichment_search_paths() -> list[Path]:
    candidates: list[Path] = []
    configured_path = Path(os.environ["SOC_IOC_ENRICHMENT_PATH"]).resolve() if "SOC_IOC_ENRICHMENT_PATH" in os.environ else None
    if configured_path is not None:
        candidates.append(configured_path)

    if getattr(sys, "frozen", False):
        base_dir = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
        candidates.append(base_dir / "AIO_security_App_New" / "src")

    workspace_root = Path(__file__).resolve().parents[2]
    candidates.append(workspace_root / "AIO_security_App_New" / "src")

    existing: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = str(candidate)
        if normalized in seen:
            continue
        seen.add(normalized)
        if candidate.exists():
            existing.append(candidate)
    return existing


def _enrich_iocs(
    entities: list[Entity],
    *,
    providers: dict[str, bool] | None = None,
    api_keys: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    ioc_module = _load_ioc_enrichment_module()
    if ioc_module is None or not hasattr(ioc_module, "scan_ioc"):
        return []

    ordered_iocs: list[str] = []
    seen: set[tuple[str, str]] = set()
    for entity in entities:
        scan_type = IOC_ENTITY_TO_SCAN_TYPE.get(entity.type)
        if scan_type is None:
            continue
        normalized_value = entity.value.strip().lower()
        if not normalized_value:
            continue
        key = (scan_type, normalized_value)
        if key in seen:
            continue
        seen.add(key)
        ordered_iocs.append(entity.value)

    enrichment: list[dict[str, Any]] = []
    for value in ordered_iocs:
        try:
            result = ioc_module.scan_ioc(value, providers=providers, api_keys=api_keys)
        except Exception as exc:
            result = {"ioc": value, "status": "error", "error": f"ioc_enrichment_failed: {exc}"}
        enrichment.append(result)
    return enrichment


def run(
    raw_log: str,
    model: Any | None = None,
    *,
    enrich_iocs: bool = False,
    ioc_providers: dict[str, bool] | None = None,
    ioc_api_keys: dict[str, str] | None = None,
) -> Result:
    event = _normalize_event(raw_log)
    entities = _extract_entities(event.raw_event, event.normalized_event)
    domains = [entity.value for entity in entities if entity.type == "domain"]
    attack_mapping = _build_attack_mappings(event.raw_event, domains, event.normalized_event)
    mapping_source = "rule"
    if not attack_mapping and model is not None:
        attack_mapping = [_build_ml_fallback_mapping(event.raw_event, model)]
        mapping_source = "ml_fallback"
    elif not attack_mapping:
        mapping_source = "none"

    if attack_mapping and mapping_source == "rule":
        epc = _build_epc(attack_mapping[0])
    elif attack_mapping and mapping_source == "ml_fallback":
        epc = _build_ml_fallback_epc(attack_mapping[0])
    else:
        epc = EPC(
            explain="Suspicious activity requires triage and containment validation.",
            plan=["Collect host and network evidence for escalation."],
            checklist=["Verify impacted assets.", "Confirm containment status."],
            confidence=0.5,
            citations=[event.raw_event[:80] or "raw_log"],
        )
    audit = {
        "pipeline_version": "deterministic-baseline-v1",
        "normalized_event": event.normalized_event,
        "entity_count": len(entities),
        "mapping_count": len(attack_mapping),
        "mapping_source": mapping_source,
    }
    if enrich_iocs:
        audit["ioc_enrichment"] = _enrich_iocs(
            entities,
            providers=ioc_providers,
            api_keys=ioc_api_keys,
        )

    return Result(entities=entities, attack_mapping=attack_mapping, epc=epc, audit=audit)
