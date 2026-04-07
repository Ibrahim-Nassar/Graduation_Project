from __future__ import annotations

SOC_LOG_FIXTURES: dict[str, dict[str, str]] = {
    "brute_force_failed_auth": {
        "minimal": (
            "failed login user=alice src_ip=10.10.10.20; "
            "login failed user=alice src_ip=10.10.10.20; "
            "invalid credentials user=alice src_ip=10.10.10.20"
        ),
        "windows_style": (
            "2026-04-06T10:11:12Z EventID=4625 Source=Microsoft-Windows-Security-Auditing "
            "An account failed to log on AccountName=alice IpAddress=10.10.10.20 Status=0xC000006D; "
            "2026-04-06T10:11:19Z EventID=4625 An account failed to log on AccountName=alice "
            "IpAddress=10.10.10.20 SubStatus=0xC000006A"
        ),
        "noisy": (
            "AUTH?? user:ALICE .. failed to log on from 10.10.10.20 ### retry=1\n"
            "garbage tokens ; authentication failed user=alice src_ip=10.10.10.20 ; "
            "+++ invalid credentials account=alice from 10.10.10.20"
        ),
    },
    "powershell_abuse": {
        "minimal": "user=alice process=powershell.exe command_line='powershell -enc QUJDRA=='",
        "windows_style": (
            "2026-04-06T13:03:10Z EventID=4688 New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
            "Creator Process Name: C:\\Windows\\System32\\cmd.exe "
            "CommandLine: powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA"
        ),
        "noisy": (
            "proc??=PowerShell.EXE ;; op=spawn ; cmdline='   PoWeRsHeLl   -enc   ZQBjAGgAbwAgAGgAaQAg  ' "
            "meta=[junk,junk2]"
        ),
    },
    "dns_tunneling_like": {
        "minimal": (
            "dns request aaaaaaaa.exfil.example.com "
            "dns request bbbbbbbb.exfil.example.com "
            "dns request cccccccc.exfil.example.com "
            "dns request dddddddd.exfil.example.com"
        ),
        "windows_style": (
            "2026-04-06T14:10:01Z EventID=22 Provider=Microsoft-Windows-DNS-Client "
            "dns query qname=hj3k9a0b.exfil.example.com QueryStatus=0; "
            "2026-04-06T14:10:03Z dns query qname=3la9cz0p.exfil.example.com; "
            "2026-04-06T14:10:05Z dns query qname=7nq1v8xr.exfil.example.com; "
            "2026-04-06T14:10:07Z dns query qname=8bz4kt2m.exfil.example.com"
        ),
        "noisy": (
            "DNS??? src=10.0.0.9 | q=aaaabbbb.exfil.example.com || "
            "dns lookup=> ccccdddd.exfil.example.com / dns query eeeeffff.exfil.example.com "
            "random text dns query 1111aaaa.exfil.example.com"
        ),
    },
    "benign_no_mapping": {
        "minimal": "user=alice successfully logged in from 10.0.0.8 and opened outlook.exe",
        "windows_style": (
            "2026-04-06T08:55:10Z EventID=4624 Source=Microsoft-Windows-Security-Auditing "
            "An account was successfully logged on AccountName=alice LogonType=2 IpAddress=10.0.0.8"
        ),
        "noisy": (
            "FYI:: workstation telemetry heartbeat ok; cpu=21%; service-check=pass; "
            "user context switched cleanly; no auth errors observed"
        ),
    },
    "noisy_messy_wording": {
        "minimal": (
            "failed login user=bob src_ip=172.16.1.9; "
            "failed login user=bob src_ip=172.16.1.9; "
            "failed login user=bob src_ip=172.16.1.9"
        ),
        "windows_style": (
            "Security-Auditing :: Event ID : 4625 :: msg='An account failed to log on' "
            "User=bob src_ip=172.16.1.9 -- repeated twice ; "
            "Event ID:4625 account failed to log on user=bob src_ip=172.16.1.9"
        ),
        "noisy": (
            "!! acct fail? yes -> account FAILED to log on ### user=bob ip=172.16.1.9 ;;; "
            "next line => authN failed user=bob src_ip=172.16.1.9 // plus junk payload "
            "last: invalid credentials account=bob from 172.16.1.9"
        ),
    },
}
