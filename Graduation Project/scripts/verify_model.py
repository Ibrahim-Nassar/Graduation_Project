"""Quick end-to-end verification: benign log, clear attack logs, and a
subtle attack that should ride the ML fallback.  Deleted after use.
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.desktop_services import analyze_soc_log


CASES = [
    ("benign login",
     "user=alice successfully logged in from 10.0.0.8 and opened outlook.exe"),
    ("benign VS Code",
     "2024-02-05T09:25:00Z WORKSTATION60 Sysmon EventID=1: Process Create. process=C:\\Program Files\\Microsoft VS Code\\Code.exe user=CORP\\dev02 parent_process=C:\\Windows\\Explorer.exe"),
    ("clear cred dump (rule)",
     "2024-02-10T09:25:00Z DC05 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\esentutl.exe cmdline=esentutl /y /vss c:\\windows\\ntds\\ntds.dit /d c:\\temp\\ntds.dit user=CORP\\attacker"),
    # Logs designed to escape all deterministic rules but still look like attacks.
    ("WMI event subscription (ML only)",
     "2024-03-01T09:00:00Z WORKSTATION900 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Register-WmiEvent -Query \"SELECT * FROM Win32_ProcessStartTrace\" -Action { } user=CORP\\attacker"),
    ("mass exfil short flow (ML only, asym not quite)",
     "{\"@timestamp\":\"2024-03-01T09:10:00Z\",\"id.orig_h\":\"10.7.2.5\",\"id.resp_h\":\"198.51.100.240\",\"id.resp_p\":443,\"proto\":\"tcp\",\"service\":\"ssl\",\"duration\":20,\"orig_bytes\":3200000,\"resp_bytes\":400000,\"conn_state\":\"SF\"}"),
    ("LSA secrets query (ML only)",
     "2024-03-01T09:20:00Z WORKSTATION901 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ChildItem 'HKLM:\\SECURITY\\Policy\\Secrets' -Recurse user=CORP\\attacker"),
    ("subtle domain trust probe (rule + sub)",
     "2024-03-01T09:30:00Z WORKSTATION902 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\nltest.exe cmdline=nltest /domain_trusts user=CORP\\attacker"),
    ("pkexec CVE-like (no rule)",
     "Feb 13 10:00:00 host185 audit: type=EXECVE pid=17050 uid=1000 cmdline=pkexec /bin/bash"),
]


def _describe(payload: dict) -> str:
    ok = payload.get("ok")
    summary = payload.get("summary", {}) or {}
    if not ok:
        return f"no_mapping (reason={payload.get('reason')})"
    tech = summary.get("technique_id", "?")
    conf = summary.get("confidence", 0.0)
    src = summary.get("mapping_source")
    tok_hint = ""
    mappings = (payload.get("result", {}) or {}).get("attack_mapping") or []
    for m in mappings:
        for r in m.get("evidence_refs") or []:
            if isinstance(r, str) and r.startswith("tokens:"):
                tok_hint = "  [tokens=" + r.removeprefix("tokens:").strip()[:60] + "...]"
                break
        if tok_hint:
            break
    return f"{tech:12s} conf={float(conf):.3f} source={src}{tok_hint}"


for label, raw in CASES:
    try:
        payload = analyze_soc_log(raw)
        print(f"{label:40s} -> {_describe(payload)}")
    except Exception as exc:
        traceback.print_exc()
        print(f"{label:40s} -> ERROR: {exc}")
