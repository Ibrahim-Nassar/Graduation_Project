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
    r"(?i)(?:"
    r"failed\s+(?:login|logon|log\s+on|authentication)"
    r"|(?:login|authentication)\s+failed"
    r"|failed\s+to\s+log\s+on"
    r"|(?:an\s+)?account\s+failed\s+to\s+log\s+on"
    r"|invalid\s+(?:password|credentials)"
    r")"
)
EVENT_ID_4625_RE = re.compile(r"(?i)\bevent(?:_id|\s+id)?\s*(?:=|:)\s*4625\b")
FOR_USER_RE = re.compile(r"(?i)\bfor\s+user\s+([a-zA-Z0-9._\\-]{2,})\b")
ACCOUNT_NAME_RE = re.compile(r"(?i)\baccount\s+name\s*:\s*([a-zA-Z0-9._\\-]{2,})\b")
IP_ADDRESS_RE = re.compile(r"(?i)\bip\s+address\s*:\s*((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b")
KV_VALUE_RE = r"(?:\"([^\"]+)\"|'([^']+)'|([^\s,;]+))"
TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)
SCHTASKS_RE = re.compile(
    r"(?i)\b(?:schtasks(?:\.exe)?|at(?:\.exe)?\s+\d|crontab)\b"
)
TASK_CREATE_RE = re.compile(
    r"(?i)(?:schtasks\s+/create|new-scheduledtask|register-scheduledtask)"
)
CRED_DUMP_RE = re.compile(
    r"(?i)\b(?:mimikatz|sekurlsa|procdump(?:\.exe)?|comsvcs\.dll|credential[_\s]*dump)\b"
)
LSASS_ACCESS_RE = re.compile(
    r"(?i)(?:lsass\.(?:exe|dmp)|procdump.*lsass|comsvcs\.dll.*(?:mini|full)dump)"
)
LOG_CLEAR_RE = re.compile(
    r"(?i)(?:wevtutil\s+cl|clear-eventlog|remove-eventlog|del\s+[^\n]*\.evtx)"
)
TIMESTOMP_RE = re.compile(r"(?i)\b(?:timestomp|setfileinfo)\b")
REMOTE_SVC_RE = re.compile(
    r"(?i)\b(?:psexec(?:\.exe)?|paexec(?:\.exe)?|winrm|invoke-command\b|"
    r"new-pssession|enter-pssession|mstsc(?:\.exe)?)\b"
)
LATERAL_RE = re.compile(
    r"(?i)(?:wmic\s+/node:|net\s+use\s+\\\\|copy\s+\\\\|xcopy\s+\\\\)"
)
PROC_INJECT_RE = re.compile(
    r"(?i)\b(?:createremotethread|ntqueueapcthread|virtualalloc(?:ex)?|"
    r"writeprocessmemory|rtlcreateuserthread|queueuserapc|"
    r"inject(?:ed|ion)?(?:\s+into|\s+process))\b"
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


def _extract_username_value(raw_log: str) -> str | None:
    username = _extract_first_kv_value(
        raw_log,
        (
            "username",
            "user",
            "user_name",
            "account",
            "account_name",
            "accountname",
            "targetusername",
            "subjectusername",
            "principal",
            "login",
            "acct",
        ),
    )
    if username:
        return username
    for_user_match = FOR_USER_RE.search(raw_log)
    if for_user_match:
        return for_user_match.group(1)
    account_name_match = ACCOUNT_NAME_RE.search(raw_log)
    if account_name_match:
        return account_name_match.group(1)
    return None


def _extract_source_ip_value(raw_log: str) -> str | None:
    source_ip = _extract_first_kv_value(
        raw_log,
        (
            "src_ip",
            "source_ip",
            "sourceip",
            "src",
            "ip",
            "ipaddress",
            "client_ip",
            "clientip",
            "remote_addr",
            "remote_ip",
            "caller_ip",
        ),
    )
    if source_ip and IPV4_RE.fullmatch(source_ip):
        return source_ip
    ip_address_match = IP_ADDRESS_RE.search(raw_log)
    if ip_address_match:
        return ip_address_match.group(1)
    fallback_match = IPV4_RE.search(raw_log)
    if fallback_match:
        return fallback_match.group(0)
    return None


def _extract_destination_ip_value(raw_log: str) -> str | None:
    destination_ip = _extract_first_kv_value(
        raw_log,
        ("dst_ip", "destination_ip", "dest_ip", "dst", "target_ip", "destinationip"),
    )
    if destination_ip and IPV4_RE.fullmatch(destination_ip):
        return destination_ip
    return None


def _extract_domain_value(raw_log: str) -> str | None:
    def _is_domain_candidate(value: str) -> bool:
        lowered = value.strip().lower()
        return bool(DOMAIN_RE.fullmatch(value)) and not lowered.endswith(".exe")

    domain = _extract_first_kv_value(
        raw_log,
        (
            "domain",
            "fqdn",
            "qname",
            "query",
            "query_name",
            "dns_query",
            "domain_name",
            "host",
            "hostname",
            "destination",
            "target",
        ),
    )
    if domain and _is_domain_candidate(domain):
        return domain
    for match in DOMAIN_RE.finditer(raw_log):
        candidate = match.group(0)
        if _is_domain_candidate(candidate):
            return candidate
    return None


def _extract_process_value(raw_log: str) -> str | None:
    process = _extract_first_kv_value(
        raw_log,
        (
            "process",
            "proc",
            "image",
            "process_name",
            "imagename",
            "new_process_name",
            "newprocessname",
            "application",
        ),
    )
    if process:
        return process
    process_name_match = re.search(r"(?i)\bnew\s+process\s+name\s*:\s*([^\r\n;]+)", raw_log)
    if process_name_match:
        process_value = process_name_match.group(1).strip()
        if process_value:
            return process_value
    match = PROCESS_RE.search(raw_log)
    if match:
        return match.group(1)
    if re.search(r"(?i)\bpowershell\b", raw_log):
        return "powershell"
    return None


def _normalize_event(raw_log: str) -> Event:
    normalized_event: dict[str, Any] = {}
    timestamp = _extract_timestamp(raw_log)
    username = _extract_username_value(raw_log)
    hostname = _extract_first_kv_value(raw_log, ("host", "hostname", "computer"))
    process = _extract_process_value(raw_log)
    command_line = _extract_first_kv_value(raw_log, ("cmdline", "command_line", "command", "cmd"))
    source_ip = _extract_source_ip_value(raw_log)
    destination_ip = _extract_destination_ip_value(raw_log)
    domain = _extract_domain_value(raw_log)
    failed_matches = list(FAILED_LOGIN_RE.finditer(raw_log))
    event_4625_matches = list(EVENT_ID_4625_RE.finditer(raw_log))
    failed_attempt_count = len(failed_matches) if failed_matches else len(event_4625_matches)

    extracted_fields: dict[str, Any] = {
        "timestamp": timestamp,
        "username": username,
        "hostname": hostname,
        "process": process,
        "command_line": command_line,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "domain": domain,
        "event_type": "failed_login" if failed_attempt_count > 0 else None,
        "failed_attempt_count": failed_attempt_count if failed_attempt_count > 0 else None,
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
        candidate = match.group(0)
        if candidate.lower().endswith(".exe"):
            continue
        _append_entity(
            entities,
            seen,
            Entity(
                type="domain",
                value=candidate,
                start=match.start(),
                end=match.end(),
                evidence_ref=candidate,
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

    failed_evidence: list[str] = []
    principal_counts: dict[str, int] = defaultdict(int)
    source_ip_counts: dict[str, int] = defaultdict(int)
    segments = [segment.strip() for segment in re.split(r"[\r\n;]+", raw_log) if segment.strip()]
    if not segments:
        segments = [raw_log]

    for segment in segments:
        failed_matches = list(FAILED_LOGIN_RE.finditer(segment))
        event_4625_match = EVENT_ID_4625_RE.search(segment)
        if not failed_matches and not event_4625_match:
            continue

        if failed_matches:
            failed_evidence.extend(match.group(0) for match in failed_matches)
        elif event_4625_match:
            failed_evidence.append(event_4625_match.group(0))

        principal = _extract_first_kv_value(segment, ("username", "user", "account", "login"))
        if principal is None:
            principal = _extract_username_value(segment)
        if principal:
            principal_counts[principal.lower()] += 1

        source_ip = _extract_source_ip_value(segment)
        if source_ip:
            source_ip_counts[source_ip] += 1
        else:
            for ipv4_match in IPV4_RE.finditer(segment):
                source_ip_counts[ipv4_match.group(0)] += 1

    failed_attempts = len(failed_evidence)
    repeated_principal = any(count >= 2 for count in principal_counts.values())
    repeated_source_ip = any(count >= 2 for count in source_ip_counts.values())
    if failed_attempts >= 3 or (failed_attempts >= 2 and (repeated_principal or repeated_source_ip)):
        evidence_refs = failed_evidence[:3]
        mappings.append(
            AttackMapping(
                technique_id="T1110",
                technique_name="Brute Force",
                confidence=0.88,
                rationale="Multiple failed authentication attempts observed in a short sequence.",
                evidence_refs=evidence_refs,
            )
        )

    schtasks_match = SCHTASKS_RE.search(raw_log)
    task_create_match = TASK_CREATE_RE.search(raw_log)
    if schtasks_match and (task_create_match or "/tn" in lowered or "create" in normalized_command):
        evidence = [schtasks_match.group(0)]
        if task_create_match:
            evidence.append(task_create_match.group(0))
        mappings.append(
            AttackMapping(
                technique_id="T1053",
                technique_name="Scheduled Task/Job",
                confidence=0.85,
                rationale="Scheduled task creation detected, potentially establishing persistence.",
                evidence_refs=evidence[:3],
            )
        )

    cred_dump_match = CRED_DUMP_RE.search(raw_log)
    lsass_match = LSASS_ACCESS_RE.search(raw_log)
    if cred_dump_match or lsass_match:
        evidence = []
        if cred_dump_match:
            evidence.append(cred_dump_match.group(0))
        if lsass_match and (not cred_dump_match or lsass_match.group(0) != cred_dump_match.group(0)):
            evidence.append(lsass_match.group(0))
        if not evidence:
            evidence = [raw_log[:80] or "raw_log"]
        conf = 0.92 if (cred_dump_match and lsass_match) else 0.85
        mappings.append(
            AttackMapping(
                technique_id="T1003",
                technique_name="OS Credential Dumping",
                confidence=conf,
                rationale="Credential dumping tool or LSASS memory access detected.",
                evidence_refs=evidence[:3],
            )
        )

    log_clear_match = LOG_CLEAR_RE.search(raw_log)
    timestomp_match = TIMESTOMP_RE.search(raw_log)
    if log_clear_match or timestomp_match:
        evidence = []
        if log_clear_match:
            evidence.append(log_clear_match.group(0))
        if timestomp_match:
            evidence.append(timestomp_match.group(0))
        mappings.append(
            AttackMapping(
                technique_id="T1070",
                technique_name="Indicator Removal",
                confidence=0.9,
                rationale="Evidence of log clearing or anti-forensics activity detected.",
                evidence_refs=evidence[:3],
            )
        )

    remote_match = REMOTE_SVC_RE.search(raw_log)
    lateral_match = LATERAL_RE.search(raw_log)
    if remote_match or lateral_match:
        evidence = []
        if remote_match:
            evidence.append(remote_match.group(0))
        if lateral_match:
            evidence.append(lateral_match.group(0))
        mappings.append(
            AttackMapping(
                technique_id="T1021",
                technique_name="Remote Services",
                confidence=0.82,
                rationale="Remote service or lateral movement tool usage detected.",
                evidence_refs=evidence[:3] or [raw_log[:80] or "raw_log"],
            )
        )

    inject_match = PROC_INJECT_RE.search(raw_log)
    if inject_match:
        mappings.append(
            AttackMapping(
                technique_id="T1055",
                technique_name="Process Injection",
                confidence=0.88,
                rationale="Process injection indicators detected (suspicious API calls or memory operations).",
                evidence_refs=[inject_match.group(0)],
            )
        )

    return mappings


def _build_epc(primary_mapping: AttackMapping, normalized_event: dict[str, Any]) -> EPC:
    evidence_preview = ", ".join(primary_mapping.evidence_refs[:2]) if primary_mapping.evidence_refs else "no direct evidence"
    username = str(normalized_event.get("username", "")).strip()
    source_ip = str(normalized_event.get("source_ip", "")).strip()
    domain = str(normalized_event.get("domain", "")).strip()
    process = str(normalized_event.get("process", "")).strip()
    failed_attempt_count = normalized_event.get("failed_attempt_count")

    if primary_mapping.technique_id == "T1059":
        process_hint = process or "powershell"
        explain = (
            f"Potential scripted command execution detected via PowerShell indicators. "
            f"Evidence observed: {evidence_preview}."
        )
        plan = [
            f"Isolate the host and collect process creation plus command-line telemetry for `{process_hint}`.",
            "Decode and review encoded command content, then confirm whether activity matches approved administration.",
        ]
        checklist = [
            "Validate parent-child process chain and execution user context.",
            "Check for follow-on actions such as credential access, persistence, or suspicious outbound connections.",
        ]
        confidence = 0.9
    elif primary_mapping.technique_id == "T1071":
        domain_hint = domain or "observed DNS domains"
        explain = (
            f"DNS activity is consistent with application-layer tunneling patterns. "
            f"Evidence observed: {evidence_preview}."
        )
        plan = [
            f"Identify hosts querying `{domain_hint}` and apply DNS/network controls to contain suspicious traffic.",
            "Correlate DNS query bursts with endpoint process telemetry and outbound session volume.",
        ]
        checklist = [
            "Measure unique/randomized subdomain frequency over short time windows.",
            "Validate whether queried domains are approved infrastructure or known malicious destinations.",
        ]
        confidence = 0.85
    elif primary_mapping.technique_id == "T1110":
        account_hint = username or "target account"
        source_hint = source_ip or "source IP"
        attempts_hint = str(failed_attempt_count) if failed_attempt_count is not None else "multiple"
        explain = (
            f"Repeated authentication failure signals suggest possible brute-force credential guessing. "
            f"Evidence observed: {evidence_preview}; failed_attempt_count={attempts_hint}."
        )
        plan = [
            f"Protect `{account_hint}` immediately (lock/reset as policy allows) and review all recent authentication outcomes.",
            f"Investigate and rate-limit or block `{source_hint}` while validating whether attempts are malicious or misconfigured automation.",
        ]
        checklist = [
            "Confirm whether a successful login followed the failed attempts.",
            "Verify MFA enforcement and authentication policy coverage for impacted identities.",
        ]
        confidence = 0.88
    elif primary_mapping.technique_id == "T1053":
        explain = (
            f"Scheduled task or job creation detected, which may establish persistent access. "
            f"Evidence observed: {evidence_preview}."
        )
        plan = [
            "Review the scheduled task parameters, including the action/command, trigger, and run-as account.",
            "Check for other persistence mechanisms and correlate with user account activity.",
        ]
        checklist = [
            "Confirm whether the task was created by an authorized administrator or automation.",
            "Verify the task command does not execute malicious payloads or download external content.",
        ]
        confidence = 0.85
    elif primary_mapping.technique_id == "T1003":
        explain = (
            f"Credential dumping activity detected, targeting stored credentials or authentication material. "
            f"Evidence observed: {evidence_preview}."
        )
        plan = [
            "Immediately contain the affected host and begin credential rotation for all potentially exposed accounts.",
            "Analyze process execution chain to determine scope and identify any exfiltrated credential material.",
        ]
        checklist = [
            "Reset passwords for all accounts that may have been exposed on the affected host.",
            "Check for follow-on lateral movement or privilege escalation using dumped credentials.",
        ]
        confidence = 0.9
    elif primary_mapping.technique_id == "T1070":
        explain = (
            f"Evidence of log clearing or anti-forensics activity detected. "
            f"Evidence observed: {evidence_preview}."
        )
        plan = [
            "Preserve remaining forensic artifacts and initiate memory acquisition from affected hosts.",
            "Reconstruct activity timeline using secondary log sources (network, SIEM, cloud).",
        ]
        checklist = [
            "Determine which log channels were cleared and the time window of deleted events.",
            "Investigate the account and process responsible for log deletion.",
        ]
        confidence = 0.9
    elif primary_mapping.technique_id == "T1021":
        source_hint = source_ip or "source"
        account_hint = username or "target"
        explain = (
            f"Remote service or lateral movement tool usage detected. "
            f"Evidence observed: {evidence_preview}."
        )
        plan = [
            f"Validate whether the remote session from `{source_hint}` to `{account_hint}` is authorized.",
            "Correlate with authentication logs and check for additional lateral movement across the environment.",
        ]
        checklist = [
            "Verify the legitimacy of the remote access tool and the user account involved.",
            "Check destination hosts for signs of compromise or unauthorized changes.",
        ]
        confidence = 0.82
    elif primary_mapping.technique_id == "T1055":
        process_hint = process or "target process"
        explain = (
            f"Process injection indicators detected, suggesting code was injected into a remote process. "
            f"Evidence observed: {evidence_preview}."
        )
        plan = [
            f"Isolate the host and capture memory dump of `{process_hint}` for forensic analysis.",
            "Identify the source process performing the injection and its execution chain.",
        ]
        checklist = [
            "Validate whether the injection API calls are from legitimate software (e.g., AV, DLP).",
            "Check for injected shellcode, reflective DLL loading, or suspicious memory allocations.",
        ]
        confidence = 0.88
    else:
        explain = (
            f"Suspicious activity requires triage and containment validation. "
            f"Evidence observed: {evidence_preview}."
        )
        plan = ["Collect host and network evidence for escalation."]
        checklist = ["Verify impacted assets.", "Confirm containment status."]
        confidence = 0.5

    return EPC(
        explain=explain,
        plan=plan,
        checklist=checklist,
        confidence=confidence,
        citations=primary_mapping.evidence_refs,
    )


def _build_ml_fallback_mapping(raw_log: str, model: Any) -> AttackMapping:
    prediction = predict_attack(raw_log, model)
    technique_id = str(prediction["technique_id"])
    technique_name_by_id = {
        "T1059": "Command and Scripting Interpreter",
        "T1071": "Application Layer Protocol",
        "T1110": "Brute Force",
        "T1053": "Scheduled Task/Job",
        "T1003": "OS Credential Dumping",
        "T1070": "Indicator Removal",
        "T1021": "Remote Services",
        "T1055": "Process Injection",
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

    for module_name in ("ioc_enrichment", "src.ioc_enrichment"):
        try:
            module = importlib.import_module(module_name)
            _IOC_MODULE_CACHE = module
            return module
        except ModuleNotFoundError:
            continue

    for ioc_src_path in _ioc_enrichment_search_paths():
        if str(ioc_src_path) not in sys.path:
            sys.path.insert(0, str(ioc_src_path))
        for module_name in ("ioc_enrichment", "src.ioc_enrichment"):
            try:
                module = importlib.import_module(module_name)
                _IOC_MODULE_CACHE = module
                return module
            except ModuleNotFoundError:
                continue
    _IOC_MODULE_CACHE = None
    return None


def _ioc_enrichment_search_paths() -> list[Path]:
    candidates: list[Path] = []
    candidates.append(Path(__file__).resolve().parent)
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
        epc = _build_epc(attack_mapping[0], event.normalized_event)
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
    if enrich_iocs and attack_mapping:
        audit["ioc_enrichment"] = _enrich_iocs(
            entities,
            providers=ioc_providers,
            api_keys=ioc_api_keys,
        )

    return Result(entities=entities, attack_mapping=attack_mapping, epc=epc, audit=audit)
