from __future__ import annotations

import importlib
import ipaddress
import json
import os
import re
from collections import defaultdict
from pathlib import Path
import sys
from typing import Any, Iterable

from src.contracts import AttackMapping, EPC, Entity, Event, Result
from src.model import predict_attack


class NoMappingError(Exception):
    """Raised when the pipeline completed successfully but no ATT&CK rule
    matched and no ML-fallback suggestion was produced.

    This is an *expected* outcome for benign traffic or inputs the rule
    table cannot currently express.  It is intentionally distinct from a
    :class:`pydantic.ValidationError`, which signals a real internal
    correctness bug (e.g. a rule produced a malformed AttackMapping).  The
    caller can catch this exception to render the "no mapping" state
    without swallowing genuine internal failures.

    The attached attributes let the UI render what context it *did* have:
    entities extracted, normalized event, and optional IOC enrichment.
    """

    def __init__(
        self,
        *,
        entities: list[Entity] | None = None,
        normalized_event: dict[str, Any] | None = None,
        ioc_enrichment: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__("no ATT&CK mapping produced")
        self.entities: list[Entity] = list(entities or [])
        self.normalized_event: dict[str, Any] = dict(normalized_event or {})
        self.ioc_enrichment: list[dict[str, Any]] | None = (
            list(ioc_enrichment) if ioc_enrichment is not None else None
        )

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
    r"(?i)\b(?:mimikatz|sekurlsa|procdump(?:\.exe)?|comsvcs\.dll|credential[_\s]*dump|"
    r"ntdsutil(?:\.exe)?|vaultcmd|reg\s+save\s+hklm\\(?:sam|system|security))\b"
)
SHADOW_READ_RE = re.compile(
    r"(?i)(?:cat|less|more|head|tail|strings)\s+(?:/etc/shadow|/etc/gshadow|/etc/master\.passwd)\b"
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

# --- New (Part 2) detection patterns ------------------------------------------------

INGRESS_TRANSFER_RE = re.compile(
    r"(?i)(?:"
    r"\bwget\s+[^\s]*https?://"
    r"|\bcurl\s+(?:-[A-Za-z]+\s+)*https?://"
    r"|\bcertutil(?:\.exe)?\s+[^\r\n]*?-urlcache"
    r"|\bbitsadmin(?:\.exe)?\s+/transfer\b"
    r"|\binvoke-webrequest\b"
    r"|\binvoke-restmethod\b"
    r"|\b(?:new-object|iex|iwr)\s+[^\r\n]*?\b(?:net\.webclient|downloadstring|downloadfile)\b"
    r")"
)
SYSTEM_BINARY_PROXY_RE = re.compile(
    r"(?i)(?:"
    r"\brundll32(?:\.exe)?\s+[^\r\n]*\.(?:dll|cpl)[,\s]"
    r"|\bregsvr32(?:\.exe)?\s+(?:[^\r\n]*\s)?/s\b[^\r\n]*/i:"
    r"|\bmshta(?:\.exe)?\s+"
    r"|\binstallutil(?:\.exe)?\s+/logfile="
    r")"
)
INHIBIT_RECOVERY_RE = re.compile(
    r"(?i)(?:"
    r"\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b"
    r"|\bvssadmin(?:\.exe)?\s+delete\s+shadows\b"
    r"|\bbcdedit(?:\.exe)?\s+[^\r\n]*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"
    r"|\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)\b"
    r")"
)
IMPAIR_DEFENSES_RE = re.compile(
    r"(?i)(?:"
    r"\bnet(?:\.exe)?\s+stop\s+(?:windefend|winmgmt|sense|wuauserv|wscsvc)\b"
    r"|\bsc(?:\.exe)?\s+(?:stop|config)\s+(?:windefend|winmgmt|sense)\b"
    r"|\bset-mppreference\s+[^\r\n]*-disable"
    r"|\bfsutil(?:\.exe)?\s+usn\s+deletejournal\b"
    r"|\bsystemctl\s+stop\s+(?:auditd|rsyslog|firewalld|fail2ban)\b"
    r")"
)
WMI_EXEC_RE = re.compile(
    r"(?i)(?:"
    r"\bwmic(?:\.exe)?\s+process\s+call\s+create\b"
    r"|\binvoke-wmimethod\b"
    r"|\bget-wmiobject\s+[^\r\n]*win32_process\b"
    r")"
)
FILE_DISCOVERY_RE = re.compile(
    r"(?i)(?:"
    r"\bfindstr(?:\.exe)?\s+(?:[^\r\n]*?\s)?/s\b"
    r"|\bdir\s+/s\s+/b\b"
    r"|\bwhere(?:\.exe)?\s+/r\s+"
    r"|\bls\s+-R\b"
    r"|\bfind\s+/\s+-(?:name|iname)\s+"
    r")"
)
ACCOUNT_CREATION_RE = re.compile(
    r"(?i)(?:"
    r"\buseradd\b|\badduser\b"
    r"|\bnet(?:\.exe)?\s+user\s+\S+\s+\S+\s+/add\b"
    r"|\bnew-localuser\b"
    r")"
)
ACCOUNT_MANIPULATION_RE = re.compile(
    r"(?i)(?:"
    r"\busermod\s+-aG\s+(?:sudo|wheel|admin|docker|adm)\b"
    r"|\bgpasswd\s+-a\b"
    r"|\bnet(?:\.exe)?\s+localgroup\s+(?:administrators|admins)\s+\S+\s+/add\b"
    r"|\badd-localgroupmember\b"
    r")"
)
UNSECURED_CREDS_RE = re.compile(
    r"(?i)(?:"
    r"\bcat\s+[^\r\n]*\.ssh/id_(?:rsa|ed25519|dsa|ecdsa)\b"
    r"|\btar\s+[^\r\n]*\.ssh\b"
    r"|\bgrep\s+-?[a-z]*[iI][a-z]*\s+(?:['\"]?(?:pass(?:word)?|credential|secret)['\"]?)"
    r"|\bfind\s+[^\r\n]+-exec\s+grep\s+-?[a-z]*[iI][a-z]*\s+['\"]?(?:pass|credential|secret)"
    # Windows-side credential-in-files searches (findstr / Select-String /
    # Get-ChildItem) where the search term is a credential keyword.
    r"|\bfindstr(?:\.exe)?\s+[^\r\n]*(?:pass(?:word)?|credential|secret|apikey|token|connectionstring)"
    r"|\bselect-string\s+[^\r\n]*(?:pass(?:word)?|credential|secret|apikey|token|connectionstring)"
    r"|\bget-childitem\s+[^\r\n]*-(?:filter|include)\s+['\"]?\*?(?:pass|cred|secret|\.config|web\.config)"
    r")"
)
EXFIL_ALT_PROTO_RE = re.compile(
    r"(?i)(?:"
    r"\bscp\s+[^\r\n]*\S+@(?:\d{1,3}\.){3}\d{1,3}:"
    r"|\brsync\s+[^\r\n]*\S+@(?:\d{1,3}\.){3}\d{1,3}:"
    r")"
)
NETWORK_SNIFFING_RE = re.compile(
    r"(?i)\b(?:tcpdump|tshark|wireshark|ettercap|dumpcap|ngrep)\b"
)
SETUID_ABUSE_RE = re.compile(
    r"(?i)(?:"
    r"\bfind\s+[^\r\n]+\s+-perm\s+-?(?:u\+s|[0-9]*4[0-9]{3})\b"
    r"|\bchmod\s+u\+s\b"
    r")"
)
SSHD_BRUTE_SINGLE_RE = re.compile(
    r"(?i)sshd\[\d+\]:\s*(?:invalid\s+user\s+\S+|failed\s+password\s+for\s+(?:invalid\s+user\s+)?\S+)"
    r"\s+from\s+(?:\d{1,3}\.){3}\d{1,3}"
)
REVERSE_SHELL_RE = re.compile(
    r"(?i)(?:"
    r"python(?:3|2)?\s+-c\s+['\"][^'\"]*?import\s+socket"
    r"|bash\s+-i\s*>&\s*/dev/tcp/"
    r"|nc(?:\.exe)?\s+-e\s+/bin/"
    r")"
)
CRONTAB_PERSISTENCE_RE = re.compile(
    r"(?i)\bcrontab\s+(?:-e|-l|-u\s+\S+)\b"
)
LOG_DELETE_LINUX_RE = re.compile(
    r"(?i)\brm\s+-rf?\s+/var/(?:log|run|cache)(?:/\S*)?"
)
SYSTEM_OWNER_DISCOVERY_RE = re.compile(
    r"(?i)(?:"
    r"\bwhoami(?:\.exe)?\b"
    r"|\bquser(?:\.exe)?\b"
    r"|\bquery\s+user\b"
    r"|\bid\s*(?:;|$|\s)"
    r"|\blogonsessions(?:\.exe)?\b"
    r")"
)
SYSTEM_NETWORK_CONFIG_RE = re.compile(
    r"(?i)(?:"
    r"\bipconfig(?:\.exe)?\s+/all\b"
    r"|\bifconfig(?:\s+-a)?\b"
    r"|\bip\s+addr\s+show\b"
    r"|\bnetsh\s+interface\b"
    r"|\bnslookup(?:\.exe)?\s+\S+"
    r"|\bsystem\s+info\b"
    r")"
)
DOMAIN_ACCOUNT_DISCOVERY_RE = re.compile(
    r"(?i)(?:"
    r"\bnet(?:\.exe)?\s+user\s+/domain\b"
    r"|\bnet(?:\.exe)?\s+group\s+[^/\r\n]*\s+/domain\b"
    r"|\bnet(?:\.exe)?\s+localgroup\s+[^\r\n]*\s+/domain\b"
    r"|\bget-aduser\b|\bget-adgroup\b|\bget-adgroupmember\b"
    r")"
)
DOMAIN_TRUST_DISCOVERY_RE = re.compile(
    r"(?i)(?:"
    r"\bnltest(?:\.exe)?\s+/(?:domain_trusts|dclist|dsgetdc)"
    r"|\bget-adtrust\b"
    r")"
)
PROCESS_DISCOVERY_RE = re.compile(
    r"(?i)(?:"
    r"\btasklist(?:\.exe)?\b"
    r"|\bget-process\b"
    r"|\bps\s+(?:-e|-ef|aux|-aux)\b"
    r"|\bpgrep\s+-?[a-z]+"
    r")"
)
SYSTEM_INFO_DISCOVERY_RE = re.compile(
    r"(?i)(?:"
    r"\bsysteminfo(?:\.exe)?\b"
    r"|\buname\s+-a\b"
    r"|\bhostnamectl\b"
    r"|\bget-computerinfo\b"
    r")"
)
QUERY_REGISTRY_RE = re.compile(
    r"(?i)(?:"
    r"\breg(?:\.exe)?\s+query\s+"
    r"|\bget-itemproperty\s+[^\r\n]*hklm"
    r"|\bregistry::hklm\\"
    r")"
)
BITS_JOB_RE = re.compile(
    r"(?i)\bbitsadmin(?:\.exe)?\s+/transfer\b"
)
# T1003.003 — OS Credential Dumping: NTDS (esentutl / vss copy of ntds.dit)
NTDS_DUMP_RE = re.compile(
    r"(?i)(?:"
    r"\besentutl(?:\.exe)?\s+[^\r\n]*ntds\.dit"
    r"|\bntdsutil(?:\.exe)?\s+[^\r\n]*ifm"
    r"|\bvssadmin\s+create\s+shadow[^\r\n]*\bc:"
    r"|\b(?:copy|xcopy|robocopy)\s+[^\r\n]*ntds\.dit"
    r")"
)
# T1059.004 — Command and Scripting Interpreter: Unix Shell (sudo/invoked bash scripts)
UNIX_SHELL_SCRIPT_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:/bin/|/usr/bin/)?(?:ba)?sh\s+(?:-[a-zA-Z]+\s+)*/(?:tmp|var/tmp|dev/shm|root)/[A-Za-z0-9_./-]+\.sh\b"
    r"|\b(?:/bin/|/usr/bin/)?(?:ba)?sh\s+-c\s+['\"][^'\"\r\n]+['\"]"
    r")"
)
# T1078.003 — Valid Accounts: Local Accounts (sshd accepting root login via password)
VALID_ROOT_LOGIN_RE = re.compile(
    r"(?i)sshd(?:\[\d+\])?:\s*accepted\s+(?:password|keyboard-interactive)\s+for\s+"
    r"root\s+from\s+((?:\d{1,3}\.){3}\d{1,3})"
)
# T1204.002 — User Execution: Malicious File (process launched from user-writable/public path)
USER_EXECUTION_RE = re.compile(
    r"(?i)[A-Z]:\\\\?Users\\\\?(?:Public|[^\\\\]+\\\\?(?:Downloads|Desktop|AppData\\\\?Local\\\\?Temp))"
    r"\\\\?[^\\\\\r\n]+\.(?:exe|scr|bat|cmd|vbs|js|hta|jar|ps1)\b"
)

IOC_ENTITY_TO_SCAN_TYPE = {
    "ipv4": "ip",
    "domain": "domain",
}
_IOC_MODULE_CACHE: Any | None = None


# ---------------------------------------------------------------------------
# Structured payload parsing (JSON — Zeek / Winlogbeat / generic).
# ---------------------------------------------------------------------------

_STRUCTURED_NULL_MARKERS: frozenset[Any] = frozenset({None, "", "NULL", "null"})
_JSON_STD_FIELD_MAP: tuple[tuple[str, str], ...] = (
    # Zeek / network telemetry (IDS)
    ("id.orig_h", "source_ip"),
    ("id.resp_h", "destination_ip"),
    ("id.orig_p", "source_port"),
    ("id.resp_p", "destination_port"),
    ("service", "service"),
    ("proto", "protocol"),
    ("duration", "duration"),
    ("orig_bytes", "bytes_sent"),
    ("resp_bytes", "bytes_received"),
    ("conn_state", "conn_state"),
    ("uid", "uid"),
    # Winlogbeat
    ("@timestamp", "timestamp"),
    ("winlog.event_id", "event_id"),
    ("winlog.event_data.TargetUserName", "username"),
    ("winlog.event_data.SubjectUserName", "username"),
    ("winlog.event_data.AccountName", "username"),
    ("winlog.event_data.NewProcessName", "process"),
    ("winlog.event_data.Image", "process"),
    ("winlog.event_data.CommandLine", "command_line"),
    ("winlog.event_data.ParentProcessName", "parent_process"),
    ("winlog.event_data.IpAddress", "source_ip"),
    ("winlog.event_data.LogonType", "logon_type"),
    ("winlog.event_data.TargetDomainName", "hostname"),
    ("winlog.computer_name", "hostname"),
)

# KV-style fields (Fortinet and similar key=value logs) that are not already
# captured by the scalar extractors above.
_KV_EXTRA_FIELD_MAP: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("service", ("service", "app", "proto_name")),
    ("destination_port", ("dstport", "destination_port", "dst_port", "dest_port")),
    ("source_port", ("srcport", "source_port", "src_port")),
    ("action", ("action", "disposition", "act")),
    ("bytes_sent", ("sentbyte", "bytes_sent", "orig_bytes", "sent_bytes")),
    ("bytes_received", ("rcvdbyte", "bytes_received", "resp_bytes", "received_bytes")),
    ("duration", ("duration",)),
    ("event_id", ("event_id", "eventid", "logid")),
    ("protocol", ("proto", "protocol")),
)


def _walk_json(obj: Any, flat: dict[str, Any], prefix: str = "") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}{key}"
            if isinstance(value, (dict, list)):
                _walk_json(value, flat, prefix=f"{path}.")
            elif isinstance(value, (str, int, float, bool)) or value is None:
                flat[path] = value
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            path = f"{prefix}{idx}"
            if isinstance(value, (dict, list)):
                _walk_json(value, flat, prefix=f"{path}.")
            elif isinstance(value, (str, int, float, bool)) or value is None:
                flat[path] = value


def _parse_structured_payload(raw_log: str) -> dict[str, Any]:
    """Extract a dict of *standardized* keys from JSON-shaped SOC logs.

    Returns an empty dict for non-JSON logs. We deliberately keep only
    scalar values (numbers, strings, bools) because everything downstream
    consumes strings; nested structures are walked to produce dotted keys.
    """
    stripped = raw_log.strip()
    if not stripped.startswith("{"):
        return {}
    try:
        payload = json.loads(stripped)
    except (ValueError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}

    flat: dict[str, Any] = {}
    _walk_json(payload, flat)

    standardized: dict[str, Any] = {}
    for json_key, std_key in _JSON_STD_FIELD_MAP:
        if json_key not in flat:
            continue
        value = flat[json_key]
        if value in _STRUCTURED_NULL_MARKERS:
            continue
        if std_key in standardized:
            continue
        if isinstance(value, float) and std_key == "event_id":
            value = str(int(value)) if value.is_integer() else str(value)
        standardized[std_key] = value if isinstance(value, (int, float)) else str(value)
    return standardized


def _is_rfc1918(ip_text: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip_text).is_private
    except (ipaddress.AddressValueError, ValueError):
        return False


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


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
            "srcip",
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
        ("dstip", "dst_ip", "destination_ip", "dest_ip", "dst", "target_ip", "destinationip"),
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


_SYSLOG_PREFIX_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[A-Za-z][A-Za-z0-9._-]*)(?:\[\d+\])?\s*:\s*"
    r"(?P<message>.*)$"
)


def _extract_linux_syslog_fields(raw_log: str) -> dict[str, Any]:
    """Best-effort extraction for Linux syslog lines (sshd, sudo, generic).

    These regexes are narrow and only fire on well-known syslog shapes so
    they cannot silently hijack non-Linux logs.
    """
    extracted: dict[str, Any] = {}

    prefix_match = _SYSLOG_PREFIX_RE.match(raw_log)
    if prefix_match:
        extracted["hostname"] = prefix_match.group("host")
        extracted["process"] = prefix_match.group("program")
        message = prefix_match.group("message").strip()
        if message:
            extracted["message"] = message

    sshd_invalid = re.search(
        r"(?i)sshd\[\d+\]:\s*invalid\s+user\s+([A-Za-z0-9._-]+)\s+from\s+"
        r"((?:\d{1,3}\.){3}\d{1,3})",
        raw_log,
    )
    if sshd_invalid:
        extracted["username"] = sshd_invalid.group(1)
        extracted["source_ip"] = sshd_invalid.group(2)
        extracted["event_type"] = "failed_login"

    sshd_failed = re.search(
        r"(?i)sshd\[\d+\]:\s*failed\s+password\s+for\s+(?:invalid\s+user\s+)?"
        r"([A-Za-z0-9._-]+)\s+from\s+((?:\d{1,3}\.){3}\d{1,3})",
        raw_log,
    )
    if sshd_failed:
        extracted.setdefault("username", sshd_failed.group(1))
        extracted.setdefault("source_ip", sshd_failed.group(2))
        extracted["event_type"] = "failed_login"

    sshd_accepted = re.search(
        r"(?i)sshd\[\d+\]:\s*accepted\s+password\s+for\s+"
        r"([A-Za-z0-9._-]+)\s+from\s+((?:\d{1,3}\.){3}\d{1,3})",
        raw_log,
    )
    if sshd_accepted:
        extracted.setdefault("username", sshd_accepted.group(1))
        extracted.setdefault("source_ip", sshd_accepted.group(2))
        extracted.setdefault("event_type", "successful_login")

    sudo_match = re.search(
        r"(?i)\bsudo:\s*([A-Za-z0-9._-]+)\s*:\s*TTY=[^;]+;\s*PWD=([^;]+);\s*"
        r"USER=([A-Za-z0-9._-]+)\s*;\s*COMMAND=(.+)$",
        raw_log,
    )
    if sudo_match:
        extracted.setdefault("username", sudo_match.group(1))
        extracted.setdefault("target_user", sudo_match.group(3))
        extracted.setdefault("command_line", sudo_match.group(4).strip())
        extracted.setdefault("process", "sudo")

    return extracted


def _normalize_event(raw_log: str) -> Event:
    normalized_event: dict[str, Any] = {}

    structured = _parse_structured_payload(raw_log)
    linux_fields = _extract_linux_syslog_fields(raw_log)

    timestamp = structured.get("timestamp") or _extract_timestamp(raw_log)
    username = (
        structured.get("username")
        or linux_fields.get("username")
        or _extract_username_value(raw_log)
    )
    hostname = (
        structured.get("hostname")
        or linux_fields.get("hostname")
        or _extract_first_kv_value(raw_log, ("host", "hostname", "computer"))
    )
    process = (
        structured.get("process")
        or linux_fields.get("process")
        or _extract_process_value(raw_log)
    )
    command_line = (
        structured.get("command_line")
        or linux_fields.get("command_line")
        or _extract_first_kv_value(raw_log, ("cmdline", "command_line", "command", "cmd"))
    )
    source_ip = (
        structured.get("source_ip")
        or linux_fields.get("source_ip")
        or _extract_source_ip_value(raw_log)
    )
    destination_ip = structured.get("destination_ip") or _extract_destination_ip_value(raw_log)
    domain = structured.get("domain") or _extract_domain_value(raw_log)

    failed_matches = list(FAILED_LOGIN_RE.finditer(raw_log))
    event_4625_matches = list(EVENT_ID_4625_RE.finditer(raw_log))
    failed_attempt_count = len(failed_matches) if failed_matches else len(event_4625_matches)
    if linux_fields.get("event_type") == "failed_login" and failed_attempt_count == 0:
        failed_attempt_count = 1

    extracted_fields: dict[str, Any] = {
        "timestamp": timestamp,
        "username": username,
        "hostname": hostname,
        "process": process,
        "command_line": command_line,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "domain": domain,
        "event_type": (
            "failed_login"
            if failed_attempt_count > 0
            else linux_fields.get("event_type")
        ),
        "failed_attempt_count": failed_attempt_count if failed_attempt_count > 0 else None,
    }

    # Extra KV-style fields (Fortinet / generic network logs).
    for std_key, keys in _KV_EXTRA_FIELD_MAP:
        if std_key in structured:
            extracted_fields.setdefault(std_key, structured[std_key])
            continue
        value = _extract_first_kv_value(raw_log, keys)
        if value is not None:
            extracted_fields[std_key] = value

    # Structured (JSON) keys we have not yet mapped but want visible in audit.
    for extra_key in ("conn_state", "protocol", "source_port", "uid", "logon_type", "parent_process"):
        if extra_key in structured and extra_key not in extracted_fields:
            extracted_fields[extra_key] = structured[extra_key]

    # Linux-syslog derived keys (free-form message body, sudo target user).
    for extra_key in ("message", "target_user"):
        if linux_fields.get(extra_key) and extra_key not in extracted_fields:
            extracted_fields[extra_key] = linux_fields[extra_key]

    for key, value in extracted_fields.items():
        if value is None or value == "":
            continue
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
    suspicious_ps_flag_match = re.search(
        r"(?i)(?:-executionpolicy\s+bypass|-nop(?:rofile)?\b|-windowstyle\s+hidden|"
        r"\biex\b|\binvoke-expression\b|\bdownloadstring\b|\bnew-object\s+net\.webclient)",
        raw_log,
    )

    if has_powershell and (has_encoded_switch or suspicious_ps_flag_match):
        powershell_match = re.search(r"(?i)\bpowershell\b", raw_log)
        enc_switch_match = re.search(r"(?i)-enc(?:odedcommand)?\b", raw_log)
        evidence_refs: list[str] = []
        if powershell_match:
            evidence_refs.append(powershell_match.group(0))
        if enc_switch_match:
            evidence_refs.append(enc_switch_match.group(0))
        elif suspicious_ps_flag_match:
            evidence_refs.append(suspicious_ps_flag_match.group(0))
        if not evidence_refs:
            evidence_refs = [raw_log[:80] or "raw_log"]
        rationale = (
            "PowerShell executed with encoded command switch."
            if has_encoded_switch
            else "PowerShell executed with suspicious execution policy / inline download pattern."
        )
        mappings.append(
            AttackMapping(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                confidence=0.9 if has_encoded_switch else 0.82,
                rationale=rationale,
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

    # --- Part 2 additions: filesystem shadow read, crontab persistence,
    # linux log wipe, ingress tool transfer, binary proxy, inhibit recovery,
    # defense impairment, WMI exec, file discovery, account create/manipulate,
    # unsecured credentials, exfil over alt protocol, network sniffing,
    # setuid abuse, reverse shells, single-line sshd brute probes, and
    # network-telemetry beacon / exfil / recon heuristics.

    shadow_match = SHADOW_READ_RE.search(raw_log)
    if shadow_match and not any(m.technique_id == "T1003" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1003",
                technique_name="OS Credential Dumping",
                confidence=0.85,
                rationale="Direct read of /etc/shadow or equivalent credential file detected.",
                evidence_refs=[shadow_match.group(0)],
            )
        )

    crontab_match = CRONTAB_PERSISTENCE_RE.search(raw_log)
    if crontab_match and not any(m.technique_id == "T1053" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1053",
                technique_name="Scheduled Task/Job",
                confidence=0.8,
                rationale="crontab modification detected (Linux scheduled job persistence).",
                evidence_refs=[crontab_match.group(0)],
            )
        )

    log_delete_linux_match = LOG_DELETE_LINUX_RE.search(raw_log)
    if log_delete_linux_match and not any(m.technique_id == "T1070" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1070",
                technique_name="Indicator Removal",
                confidence=0.88,
                rationale="Bulk deletion of Linux system log directory detected.",
                evidence_refs=[log_delete_linux_match.group(0)],
            )
        )

    # T1003.003 — NTDS dump (esentutl copying ntds.dit, ntdsutil ifm, vss).
    ntds_match = NTDS_DUMP_RE.search(raw_log)
    if ntds_match and not any(m.technique_id == "T1003" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1003",
                technique_name="OS Credential Dumping",
                confidence=0.88,
                rationale="NTDS.dit copy / ntdsutil IFM / esentutl dump detected.",
                evidence_refs=[ntds_match.group(0)],
            )
        )

    # Emit T1197 (BITS Jobs) BEFORE the generic T1105 ingress check so the
    # bitsadmin /transfer case maps to BITS Jobs as the primary technique,
    # with T1105 retained as a secondary mapping via the ingress branch below.
    bits_match = BITS_JOB_RE.search(raw_log)
    if bits_match:
        mappings.append(
            AttackMapping(
                technique_id="T1197",
                technique_name="BITS Jobs",
                confidence=0.85,
                rationale="bitsadmin /transfer observed (Background Intelligent Transfer Service).",
                evidence_refs=[bits_match.group(0)],
            )
        )

    ingress_match = INGRESS_TRANSFER_RE.search(raw_log)
    if ingress_match:
        mappings.append(
            AttackMapping(
                technique_id="T1105",
                technique_name="Ingress Tool Transfer",
                confidence=0.85,
                rationale="External payload download utility observed (wget/curl/certutil/bitsadmin/PowerShell download).",
                evidence_refs=[ingress_match.group(0)],
            )
        )

    binary_proxy_match = SYSTEM_BINARY_PROXY_RE.search(raw_log)
    if binary_proxy_match:
        mappings.append(
            AttackMapping(
                technique_id="T1218",
                technique_name="System Binary Proxy Execution",
                confidence=0.82,
                rationale="Execution via trusted Windows binary proxy (rundll32/regsvr32/mshta/installutil).",
                evidence_refs=[binary_proxy_match.group(0)],
            )
        )

    inhibit_recovery_match = INHIBIT_RECOVERY_RE.search(raw_log)
    if inhibit_recovery_match:
        mappings.append(
            AttackMapping(
                technique_id="T1490",
                technique_name="Inhibit System Recovery",
                confidence=0.9,
                rationale="Shadow copy or recovery artefact deletion detected.",
                evidence_refs=[inhibit_recovery_match.group(0)],
            )
        )

    impair_match = IMPAIR_DEFENSES_RE.search(raw_log)
    if impair_match:
        mappings.append(
            AttackMapping(
                technique_id="T1562",
                technique_name="Impair Defenses",
                confidence=0.85,
                rationale="Stopping or disabling a security / logging service detected.",
                evidence_refs=[impair_match.group(0)],
            )
        )

    wmi_exec_match = WMI_EXEC_RE.search(raw_log)
    if wmi_exec_match:
        mappings.append(
            AttackMapping(
                technique_id="T1047",
                technique_name="Windows Management Instrumentation",
                confidence=0.82,
                rationale="Process creation via WMI detected.",
                evidence_refs=[wmi_exec_match.group(0)],
            )
        )

    # Credential-in-files searches must be classified before the generic
    # T1083 (File and Directory Discovery) rule because a recursive
    # ``findstr /s`` for "password" is unambiguously a credential hunt, not
    # plain discovery. The T1552 rule is therefore evaluated first and
    # suppresses T1083 when it fires.
    unsecured_creds_match_early = UNSECURED_CREDS_RE.search(raw_log)
    if unsecured_creds_match_early and not any(
        m.technique_id == "T1552" for m in mappings
    ):
        mappings.append(
            AttackMapping(
                technique_id="T1552",
                technique_name="Unsecured Credentials",
                confidence=0.8,
                rationale=(
                    "Filesystem search for credential/secret keywords detected "
                    "(credentials-in-files intent)."
                ),
                evidence_refs=[unsecured_creds_match_early.group(0)],
            )
        )

    file_disc_match = FILE_DISCOVERY_RE.search(raw_log)
    if file_disc_match and not any(m.technique_id == "T1552" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1083",
                technique_name="File and Directory Discovery",
                confidence=0.72,
                rationale="Recursive filesystem enumeration detected.",
                evidence_refs=[file_disc_match.group(0)],
            )
        )

    account_create_match = ACCOUNT_CREATION_RE.search(raw_log)
    if account_create_match:
        mappings.append(
            AttackMapping(
                technique_id="T1136",
                technique_name="Create Account",
                confidence=0.8,
                rationale="Local account creation command detected.",
                evidence_refs=[account_create_match.group(0)],
            )
        )

    account_manip_match = ACCOUNT_MANIPULATION_RE.search(raw_log)
    if account_manip_match:
        mappings.append(
            AttackMapping(
                technique_id="T1098",
                technique_name="Account Manipulation",
                confidence=0.82,
                rationale="Privileged group membership change detected.",
                evidence_refs=[account_manip_match.group(0)],
            )
        )

    unsecured_creds_match = UNSECURED_CREDS_RE.search(raw_log)
    if unsecured_creds_match and not any(m.technique_id == "T1552" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1552",
                technique_name="Unsecured Credentials",
                confidence=0.78,
                rationale="Credential / secret harvesting pattern detected in filesystem command.",
                evidence_refs=[unsecured_creds_match.group(0)],
            )
        )

    exfil_alt_match = EXFIL_ALT_PROTO_RE.search(raw_log)
    if exfil_alt_match:
        mappings.append(
            AttackMapping(
                technique_id="T1048",
                technique_name="Exfiltration Over Alternative Protocol",
                confidence=0.82,
                rationale="scp/rsync transfer to remote IP observed.",
                evidence_refs=[exfil_alt_match.group(0)],
            )
        )

    sniff_match = NETWORK_SNIFFING_RE.search(raw_log)
    if sniff_match:
        mappings.append(
            AttackMapping(
                technique_id="T1040",
                technique_name="Network Sniffing",
                confidence=0.78,
                rationale="Packet capture tool invocation detected.",
                evidence_refs=[sniff_match.group(0)],
            )
        )

    setuid_match = SETUID_ABUSE_RE.search(raw_log)
    if setuid_match:
        mappings.append(
            AttackMapping(
                technique_id="T1548",
                technique_name="Abuse Elevation Control Mechanism",
                confidence=0.75,
                rationale="Search or modification of setuid binaries detected.",
                evidence_refs=[setuid_match.group(0)],
            )
        )

    reverse_shell_match = REVERSE_SHELL_RE.search(raw_log)
    if reverse_shell_match and not any(m.technique_id == "T1059" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                confidence=0.85,
                rationale="Reverse-shell style interpreter invocation detected.",
                evidence_refs=[reverse_shell_match.group(0)],
            )
        )

    # T1059.004 — Unix Shell (sudo launching a script from a user/tmp path, or
    # ``bash -c`` style inline shell commands). Skip if a higher-signal T1059
    # rule (reverse shell, PowerShell) has already fired.
    unix_shell_match = UNIX_SHELL_SCRIPT_RE.search(raw_log)
    if unix_shell_match and not any(m.technique_id == "T1059" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                confidence=0.72,
                rationale="Unix shell script invocation from a user-writable path detected.",
                evidence_refs=[unix_shell_match.group(0)],
            )
        )

    # T1078.003 — Valid Accounts: Local Accounts. The corpus labels sshd
    # successful password/keyboard-interactive logins for ``root`` as abuse of
    # a valid local account.
    valid_root_match = VALID_ROOT_LOGIN_RE.search(raw_log)
    if valid_root_match and not any(m.technique_id == "T1078" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1078",
                technique_name="Valid Accounts",
                confidence=0.7,
                rationale="Successful interactive sshd login as root detected.",
                evidence_refs=[valid_root_match.group(0)],
            )
        )

    # Single-line sshd probe: the current brute-force rule requires >=3 attempts
    # per log. Real-world syslog typically records one attempt per line, and the
    # validated corpus labels each such line as T1110.001. Fire at moderate
    # confidence only when no brute-force mapping has already been produced.
    sshd_brute_match = SSHD_BRUTE_SINGLE_RE.search(raw_log)
    if sshd_brute_match and not any(m.technique_id == "T1110" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1110",
                technique_name="Brute Force",
                confidence=0.7,
                rationale="sshd Invalid user / Failed password probe detected (single-event brute force candidate).",
                evidence_refs=[sshd_brute_match.group(0)],
            )
        )

    system_owner_match = SYSTEM_OWNER_DISCOVERY_RE.search(raw_log)
    if system_owner_match:
        mappings.append(
            AttackMapping(
                technique_id="T1033",
                technique_name="System Owner/User Discovery",
                confidence=0.72,
                rationale="System owner / current-user discovery command detected.",
                evidence_refs=[system_owner_match.group(0)],
            )
        )

    system_network_match = SYSTEM_NETWORK_CONFIG_RE.search(raw_log)
    if system_network_match:
        mappings.append(
            AttackMapping(
                technique_id="T1016",
                technique_name="System Network Configuration Discovery",
                confidence=0.72,
                rationale="Local network configuration enumeration command detected.",
                evidence_refs=[system_network_match.group(0)],
            )
        )

    domain_account_match = DOMAIN_ACCOUNT_DISCOVERY_RE.search(raw_log)
    if domain_account_match:
        mappings.append(
            AttackMapping(
                technique_id="T1087",
                technique_name="Account Discovery",
                confidence=0.75,
                rationale="Domain account enumeration command detected.",
                evidence_refs=[domain_account_match.group(0)],
            )
        )

    domain_trust_match = DOMAIN_TRUST_DISCOVERY_RE.search(raw_log)
    if domain_trust_match:
        mappings.append(
            AttackMapping(
                technique_id="T1482",
                technique_name="Domain Trust Discovery",
                confidence=0.78,
                rationale="Domain trust enumeration command detected.",
                evidence_refs=[domain_trust_match.group(0)],
            )
        )

    process_disc_match = PROCESS_DISCOVERY_RE.search(raw_log)
    if process_disc_match:
        mappings.append(
            AttackMapping(
                technique_id="T1057",
                technique_name="Process Discovery",
                confidence=0.7,
                rationale="Running-process enumeration command detected.",
                evidence_refs=[process_disc_match.group(0)],
            )
        )

    system_info_match = SYSTEM_INFO_DISCOVERY_RE.search(raw_log)
    if system_info_match:
        mappings.append(
            AttackMapping(
                technique_id="T1082",
                technique_name="System Information Discovery",
                confidence=0.72,
                rationale="Operating-system / host info enumeration command detected.",
                evidence_refs=[system_info_match.group(0)],
            )
        )

    query_registry_match = QUERY_REGISTRY_RE.search(raw_log)
    if query_registry_match:
        mappings.append(
            AttackMapping(
                technique_id="T1012",
                technique_name="Query Registry",
                confidence=0.72,
                rationale="Windows registry enumeration command detected.",
                evidence_refs=[query_registry_match.group(0)],
            )
        )

    # T1204.002 — User Execution: Malicious File. This rule only inspects the
    # normalized ``process`` field so it cannot fire on a BITS/certutil/etc.
    # download target parsed out of a command line (those are T1105/T1197).
    # It also runs last so it only becomes the *primary* mapping when no other
    # higher-signal technique has already matched.
    process_path = normalized_event.get("process") if isinstance(normalized_event, dict) else None
    if isinstance(process_path, str) and process_path:
        user_exec_match = USER_EXECUTION_RE.search(process_path)
        if user_exec_match and not any(m.technique_id == "T1204" for m in mappings):
            mappings.append(
                AttackMapping(
                    technique_id="T1204",
                    technique_name="User Execution",
                    confidence=0.65,
                    rationale="Process image launched from a user-writable location (Public/Downloads/Temp).",
                    evidence_refs=[user_exec_match.group(0)],
                )
            )

    # Network-telemetry heuristics: beaconing, exfil, recon, remote services.
    _append_network_telemetry_mappings(mappings, raw_log, normalized_event)

    return mappings


def _append_network_telemetry_mappings(
    mappings: list[AttackMapping],
    raw_log: str,
    normalized_event: dict[str, Any],
) -> None:
    """Rules derived from normalized network fields (firewall / Zeek JSON).

    These rules only fire when structured fields are present, so KV- and
    JSON-shaped logs get coverage without regexing raw text.
    """

    action = str(normalized_event.get("action", "")).strip().lower()
    service = str(normalized_event.get("service", "")).strip().lower()
    conn_state = str(normalized_event.get("conn_state", "")).strip().upper()
    dst_port_raw = normalized_event.get("destination_port")
    bytes_sent = _as_float(normalized_event.get("bytes_sent"))
    bytes_received = _as_float(normalized_event.get("bytes_received"))
    duration = _as_float(normalized_event.get("duration"))
    dst_ip = str(normalized_event.get("destination_ip", "")).strip()

    try:
        dst_port = int(str(dst_port_raw)) if dst_port_raw is not None else None
    except (TypeError, ValueError):
        dst_port = None

    http_like = service in {"http", "https", "ssl", "tls"} or dst_port in {80, 443, 8080, 8443}
    accepted = action in {"accept", "allow", "allowed", "permit"} or (
        not action and conn_state in {"SF", "S1", "S0"}
    )
    denied = action in {"deny", "denied", "drop", "block", "blocked", "reject"} or conn_state in {
        "REJ",
        "RSTO",
        "RSTOS0",
    }

    # Exfiltration over C2 channel — large asymmetric outbound volume.
    if (
        bytes_sent is not None
        and bytes_sent >= 10_000_000
        and (bytes_received is None or bytes_received == 0 or bytes_sent >= 5 * max(bytes_received, 1))
    ):
        if not any(m.technique_id == "T1041" for m in mappings):
            mappings.append(
                AttackMapping(
                    technique_id="T1041",
                    technique_name="Exfiltration Over C2 Channel",
                    confidence=0.82,
                    rationale=(
                        f"Asymmetric high-volume outbound traffic: bytes_sent={int(bytes_sent)} "
                        f"bytes_received={int(bytes_received) if bytes_received is not None else 'n/a'}."
                    ),
                    evidence_refs=[raw_log[:160] or "network_flow"],
                )
            )

    # Precedence: beaconing (T1071) is checked before recon (T1595) so that
    # http/https traffic with no server response is classified as application
    # layer beaconing rather than generic scanning, even for Zeek conn_state=S0.
    short_low_volume_beacon = (
        not denied
        and (http_like or service in {"ssh"} or dst_port in {22})
        and bytes_sent is not None
        and bytes_received is not None
        and 0 < bytes_sent <= 500
        and 0 <= bytes_received <= 500
        and duration is not None
        and 0 < duration <= 5
    )
    beacon_hit = short_low_volume_beacon or (
        http_like
        and not denied
        and bytes_sent is not None
        and bytes_received is not None
        and bytes_received == 0
        and bytes_sent <= 2000
    )
    if beacon_hit and not any(m.technique_id == "T1071" for m in mappings):
        mappings.append(
            AttackMapping(
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                confidence=0.78,
                rationale=(
                    "Low-volume asymmetric HTTP/HTTPS flow with no server response "
                    "is consistent with C2 beaconing."
                ),
                evidence_refs=[raw_log[:160] or "network_flow"],
            )
        )

    # Active scanning / recon — denied traffic or early-abort connection with
    # minimal payload. Only fires when beaconing did not already fire.
    recon_hit = (
        denied
        or (
            conn_state in {"REJ", "RSTO", "RSTOS0", "S0"}
            and not http_like
            and (bytes_received is None or bytes_received == 0)
            and (bytes_sent is None or bytes_sent <= 2000)
        )
    )
    if (
        recon_hit
        and dst_ip
        and not beacon_hit
        and not any(m.technique_id == "T1595" for m in mappings)
    ):
        mappings.append(
            AttackMapping(
                technique_id="T1595",
                technique_name="Active Scanning",
                confidence=0.7,
                rationale=(
                    "Denied or rejected network attempt with minimal payload "
                    "consistent with reconnaissance."
                ),
                evidence_refs=[raw_log[:160] or "network_flow"],
            )
        )

    # RDP / SSH remote services — accepted external flow with meaningful volume.
    if (
        accepted
        and dst_port in {3389, 22}
        and dst_ip
        and (
            (bytes_sent is not None and bytes_sent >= 100_000)
            or (duration is not None and duration >= 1800)
        )
    ):
        if not any(m.technique_id == "T1021" for m in mappings):
            service_hint = "RDP" if dst_port == 3389 else "SSH"
            mappings.append(
                AttackMapping(
                    technique_id="T1021",
                    technique_name="Remote Services",
                    confidence=0.75,
                    rationale=(
                        f"Accepted {service_hint} session to {dst_ip} with sustained "
                        f"traffic or duration indicates remote service usage."
                    ),
                    evidence_refs=[raw_log[:160] or "network_flow"],
                )
            )


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


# Minimum classifier confidence for ML fallback to surface a technique.
# Below this, we keep "no mapping" rather than presenting a weak guess.
#
# Tuned for the *calibrated* classifier (CalibratedClassifierCV + balanced
# LogReg over word+char n-grams) introduced in train_model v2.  Calibrated
# sigmoid scores are much less inflated than the raw LogReg scores the old
# thresholds (0.50 / 0.15) were set against, so an equivalent gate lives
# around ~0.25.  Combined with the BENIGN class and the margin check below,
# this keeps guessing in check while restoring coverage on genuine attack
# predictions whose calibrated top-1 sits in the 0.25-0.45 range.
ML_FALLBACK_CONFIDENCE_THRESHOLD = 0.25

# Minimum probability margin between the top-1 and top-2 predicted classes.
# When two classes are nearly tied the model is uncertain about which
# technique best describes the event; in that case it is safer to return
# "no mapping" than to surface a low-differentiation guess.  Lowered
# alongside the confidence threshold for the calibrated model.
ML_FALLBACK_MARGIN_THRESHOLD = 0.08

# Human-readable names for ATT&CK techniques the fallback classifier can
# output. Only techniques trained on the labeled corpus appear here; any
# other id falls back to a neutral label that the UI can still render.
_ML_TECHNIQUE_NAMES: dict[str, str] = {
    "T1003": "OS Credential Dumping",
    "T1012": "Query Registry",
    "T1016": "System Network Configuration Discovery",
    "T1021": "Remote Services",
    "T1033": "System Owner/User Discovery",
    "T1040": "Network Sniffing",
    "T1041": "Exfiltration Over C2 Channel",
    "T1047": "Windows Management Instrumentation",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1070": "Indicator Removal",
    "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1136": "Create Account",
    "T1197": "BITS Jobs",
    "T1204": "User Execution",
    "T1218": "System Binary Proxy Execution",
    "T1482": "Domain Trust Discovery",
    "T1490": "Inhibit System Recovery",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials",
    "T1562": "Impair Defenses",
    "T1595": "Active Scanning",
}


def _effective_thresholds(
    model: Any,
    *,
    threshold: float,
    margin_threshold: float,
) -> tuple[float, float]:
    """Return (confidence, margin) thresholds, preferring values baked into
    the model artifact when present.

    The improved training pipeline auto-tunes the decision thresholds
    against the BENIGN-vs-attack precision/recall curve and attaches the
    chosen pair to ``model.tuned_thresholds``.  When that is available we
    prefer it over the hand-picked defaults.  Older artifacts without
    tuned thresholds fall back to the module constants so existing
    deployments keep working.
    """
    tuned = getattr(model, "tuned_thresholds", None)
    if isinstance(tuned, dict):
        try:
            threshold = float(tuned.get("confidence_threshold", threshold))
            margin_threshold = float(tuned.get("margin_threshold", margin_threshold))
        except (TypeError, ValueError):
            pass
    return threshold, margin_threshold


_TOKEN_PREFIX_RE = re.compile(r"^(?:word|char)__")
_TOKEN_PART_NOISE_RE = re.compile(
    r"""
    ^\d+$                       # bare numbers, e.g. "1024"
    | ^\d{1,2}[:\-/]\d{1,2}$    # short time-ish chunks "02:10" / "02-10"
    | ^\d+t\d+$                 # timestamp halves like "10t18"
    | ^t\d+$                    # "t1", "t09"
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _is_noise_token(token: str) -> bool:
    """Return ``True`` when *every* whitespace-separated part of ``token``
    is a numeric/time fragment.

    The vectorizer often surfaces n-gram features such as ``"02 10t18"`` or
    ``"10 time"`` because every example of a given log family shares the
    same datestamp prefix.  Those are not informative for the analyst —
    they are an artefact of the corpus, not evidence from this log — so
    we drop them before rendering.
    """
    parts = [p for p in token.split() if p]
    if not parts:
        return True
    return all(_TOKEN_PART_NOISE_RE.match(p) for p in parts)


def _clean_rationale_tokens(raw_tokens: Iterable[Any], limit: int = 5) -> list[str]:
    """Turn raw vectorizer feature names into short analyst-friendly terms.

    The training pipeline names its features with ``word__`` / ``char__``
    prefixes (from :class:`~sklearn.pipeline.FeatureUnion`).  Those prefixes
    are helpful in a training report but look like debug noise when shown
    in the analyst UI, so we strip them.  We also skip tokens that are
    purely timestamp/number fragments because quoting them as "evidence"
    in the UI misleads the analyst — those features only fire because the
    training logs happen to share that timestamp prefix.
    """
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in raw_tokens:
        if not isinstance(raw, str):
            continue
        token = _TOKEN_PREFIX_RE.sub("", raw).strip()
        if not token or _is_noise_token(token):
            continue
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(token)
        if len(cleaned) >= limit:
            break
    return cleaned


# If BENIGN wins over the best attack class by less than this much, we
# treat it as genuine uncertainty rather than a confident benign verdict
# and surface the top attack class with a prominent low-confidence label.
# The analyst still sees the lead they would otherwise have missed, but
# the rationale explicitly warns them the model was torn between "benign"
# and the suggested technique.
_BENIGN_SOFT_MARGIN = 0.20


def _best_attack_from_ranked(
    ranked: list[tuple[str, float]] | Any,
) -> tuple[str, float] | None:
    """Return the first ``(class, prob)`` pair that is *not* ``BENIGN``.

    Accepts ``Any`` so callers can pass the value straight from
    ``prediction.get("ranked_classes")`` without defensive plumbing.
    """
    if not isinstance(ranked, list):
        return None
    for entry in ranked:
        if not isinstance(entry, tuple) or len(entry) != 2:
            continue
        label, prob = entry
        if not isinstance(label, str) or label == "BENIGN" or not label:
            continue
        try:
            return label, float(prob)
        except (TypeError, ValueError):
            continue
    return None


def _build_ml_fallback_mapping(
    raw_log: str,
    model: Any,
    *,
    threshold: float = ML_FALLBACK_CONFIDENCE_THRESHOLD,
    margin_threshold: float = ML_FALLBACK_MARGIN_THRESHOLD,
) -> AttackMapping | None:
    """Run the ML fallback classifier against ``raw_log``.

    Returns ``None`` when the model is *confidently* benign, otherwise
    returns a mapping.  The behaviour for each branch is:

    * ``BENIGN`` wins by a clear margin (``>= _BENIGN_SOFT_MARGIN``) →
      suppress, the log is almost certainly non-malicious.
    * ``BENIGN`` wins narrowly → surface the best *attack* class instead,
      flagged as low-confidence so the analyst still sees a lead (this
      catches short prose logs whose lack of timestamp makes the model
      weakly prefer BENIGN despite real attack indicators).
    * An attack class wins → standard gates on confidence and margin.

    When a prediction passes the gate, the returned ``AttackMapping``
    includes analyst-visible rationale tokens (top TF-IDF features for
    the class) and is promoted to a sub-technique id when the model's
    sub-head produced a confident refinement.
    """
    effective_confidence, effective_margin = _effective_thresholds(
        model, threshold=threshold, margin_threshold=margin_threshold
    )

    prediction = predict_attack(raw_log, model)
    technique_id = str(prediction["technique_id"])
    confidence = float(prediction["confidence"])
    margin = float(prediction.get("margin", 0.0))

    is_low_confidence_benign = False
    if technique_id == "BENIGN":
        best_attack = _best_attack_from_ranked(prediction.get("ranked_classes"))
        if best_attack is None:
            return None
        attack_label, attack_prob = best_attack
        benign_vs_attack_margin = confidence - attack_prob
        # Confident benign → suppress.
        if benign_vs_attack_margin >= _BENIGN_SOFT_MARGIN:
            return None
        # Narrow benign lead → surface the attack as low-confidence.
        technique_id = attack_label
        confidence = attack_prob
        margin = benign_vs_attack_margin  # now a small positive number
        is_low_confidence_benign = True
    else:
        if confidence < effective_confidence:
            return None
        if margin < effective_margin:
            return None

    sub_technique_id = prediction.get("sub_technique_id")
    raw_rationale_tokens = prediction.get("rationale_tokens") or []
    rationale_tokens = _clean_rationale_tokens(raw_rationale_tokens, limit=5)

    reported_id = (
        str(sub_technique_id)
        if isinstance(sub_technique_id, str)
        and sub_technique_id
        and not is_low_confidence_benign
        else technique_id
    )
    technique_name = _ML_TECHNIQUE_NAMES.get(technique_id, "Model Predicted Technique")

    if is_low_confidence_benign:
        rationale = (
            "ML fallback prediction — the classifier was uncertain between "
            "benign and attack activity but leaned toward this technique; "
            "treat as a weak lead and corroborate with other evidence."
        )
    else:
        rationale = (
            "ML fallback prediction — no deterministic ATT&CK rule matched, so "
            "the classifier chose the closest technique; analyst review "
            "required."
        )
    if rationale_tokens:
        preview = ", ".join(f"\u2018{tok}\u2019" for tok in rationale_tokens[:4])
        rationale = f"{rationale} Key terms the model keyed on: {preview}."

    evidence: list[str] = ["ml_prediction"]
    if is_low_confidence_benign:
        evidence.append("benign_vs_attack_tied")
    if rationale_tokens:
        evidence.append("key_terms:" + ", ".join(rationale_tokens))

    return AttackMapping(
        technique_id=reported_id,
        technique_name=technique_name,
        confidence=confidence,
        rationale=rationale,
        evidence_refs=evidence,
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


# Severity tier used when ordering attack mappings for primary selection.
# Higher tier = more important.  Keep this tight and honest; ties fall back
# to confidence.  Techniques not listed get a neutral tier.  This intentionally
# mirrors the semantic weight of ``desktop_services._HIGH_SEVERITY_TECHNIQUES``
# / ``_MEDIUM_SEVERITY_TECHNIQUES`` so the picked primary drives a coherent
# severity in the UI.
_PRIMARY_SEVERITY_TIER: dict[str, int] = {
    # Critical-weight credential / injection / exfiltration techniques.
    "T1003": 4,  # Credential dumping
    "T1055": 4,  # Process injection
    "T1041": 4,  # Exfil over C2
    "T1490": 4,  # Inhibit system recovery
    # High-weight execution / C2 / lateral-movement / persistence.
    "T1059": 3,  # Command & scripting interpreter
    "T1071": 3,  # Application layer protocol (C2)
    "T1021": 3,  # Remote services / lateral movement
    "T1053": 3,  # Scheduled task
    "T1070": 3,  # Indicator removal / log tamper
    "T1110": 3,  # Brute force
    "T1548": 3,  # Abuse elevation control
    "T1562": 3,  # Impair defenses
    "T1105": 3,  # Ingress tool transfer
    "T1197": 3,  # BITS jobs
    # Medium-weight staging / discovery we still want above plain recon.
    "T1218": 2,  # Signed binary proxy execution
    "T1078": 2,  # Valid accounts
    "T1098": 2,  # Account manipulation
    "T1136": 2,  # Create account
    "T1204": 2,  # User execution
    # Low-weight discovery / recon stays last.
    "T1012": 1,
    "T1016": 1,
    "T1033": 1,
    "T1040": 1,
    "T1047": 1,
    "T1057": 1,
    "T1082": 1,
    "T1087": 1,
    "T1482": 1,
    "T1552": 1,
    "T1595": 1,
}


def _primary_sort_key(mapping: AttackMapping) -> tuple[int, float]:
    """Sort key used to pick the *primary* mapping from a list.

    Higher is better.  Severity tier dominates; confidence breaks ties so a
    pair of rules in the same tier falls back to the more confident one.
    """
    # Trim sub-techniques ("T1548.002") to the parent technique for tiering.
    technique_id = mapping.technique_id.split(".", 1)[0]
    tier = _PRIMARY_SEVERITY_TIER.get(technique_id, 0)
    return (tier, float(mapping.confidence))


def _order_mappings_by_importance(mappings: list[AttackMapping]) -> list[AttackMapping]:
    """Return mappings ordered with the most important one first.

    "Most important" = higher severity tier, then higher confidence.  This
    is a stable sort so equally-ranked mappings preserve their original
    rule-match order — i.e. we never shuffle things we don't need to.
    """
    if len(mappings) <= 1:
        return list(mappings)
    return sorted(mappings, key=_primary_sort_key, reverse=True)


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
        fallback = _build_ml_fallback_mapping(event.raw_event, model)
        if fallback is not None:
            attack_mapping = [fallback]
            mapping_source = "ml_fallback"
        else:
            mapping_source = "none"
    elif not attack_mapping:
        mapping_source = "none"

    if not attack_mapping:
        # Explicit "no mapping" signal.  We *must not* let this fall through
        # to ``Result(...)`` and raise a generic ``ValidationError`` — that
        # would be indistinguishable from a real internal correctness bug
        # (e.g. a rule producing a malformed AttackMapping).  Callers catch
        # :class:`NoMappingError` to render the benign unmapped state while
        # leaving any other ValidationError to surface as a real failure.
        ioc_enrichment_payload: list[dict[str, Any]] | None = None
        if enrich_iocs:
            ioc_enrichment_payload = _enrich_iocs(
                entities,
                providers=ioc_providers,
                api_keys=ioc_api_keys,
            )
        raise NoMappingError(
            entities=entities,
            normalized_event=event.normalized_event,
            ioc_enrichment=ioc_enrichment_payload,
        )

    # Pick the primary mapping by severity then confidence so the summary
    # reflects the most *important* technique, not whichever rule happened
    # to match first.  All mappings are preserved below.
    attack_mapping = _order_mappings_by_importance(attack_mapping)
    primary_mapping = attack_mapping[0]

    if mapping_source == "rule":
        epc = _build_epc(primary_mapping, event.normalized_event)
    else:  # ml_fallback
        epc = _build_ml_fallback_epc(primary_mapping)
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
