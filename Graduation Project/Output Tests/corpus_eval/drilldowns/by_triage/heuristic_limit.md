# Triage: heuristic_limit

All failing assertions classified as `heuristic_limit`.

_category=heuristic_limit, size=11_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 145 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 147 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 148 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 151 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 152 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 155 | Linux | Syslog | Benign | — | — | info | none | `subtype_match` | `heuristic_limit` |
| 180 | Linux | Syslog | Malformed | — | — | info | none | `family_match`, `subtype_match` | `heuristic_limit` |
| 180 | Linux | Syslog | Malformed | — | — | info | none | `family_match`, `subtype_match` | `heuristic_limit` |
| 188 | Linux | Syslog | Mixed | — | `T1078` | medium | rule | `subtype_match`, `attack_mapping_presence` | `corpus_ambiguity`, `heuristic_limit` |
| 189 | Linux | Syslog | Mixed | `T1040` | `T1040` | medium | rule | `subtype_match` | `heuristic_limit` |
| 190 | Linux | Syslog | Mixed | `T1548.001` | `T1548` | medium | rule | `subtype_match` | `heuristic_limit` |

## Records

### Record 145

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:05 srv-linux-01 sshd[3015]: Connection closed by authenticating user j.doe 10.10.25.10 port 51222 [preauth]
```

### Record 147

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 7 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:15 srv-linux-01 sudo:    j.doe : TTY=pts/0 ; PWD=/home/j.doe ; USER=root ; COMMAND=/usr/bin/apt update
```

### Record 148

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:20 srv-linux-01 sshd[3020]: Accepted publickey for j.doe from 10.10.25.10 port 51223 ssh2: RSA SHA256:abc
```

### Record 151

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:35 srv-linux-01 sshd[3030]: pam_unix(sshd:session): session opened for user j.doe by (uid=0)
```

### Record 152

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 7 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:40 srv-linux-01 sudo:    j.doe : TTY=pts/0 ; PWD=/home/j.doe ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/syslog
```

### Record 155

- Family / subtype: `Linux` / `Syslog`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:00:55 srv-linux-01 sshd[3050]: pam_unix(sshd:session): session closed for user j.doe
```

### Record 180

- Family / subtype: `Linux` / `Syslog`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `family_match`, `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 0 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:45:00 srv-linux-01 : %LOG_SYSTEM_FAILURE% error_code=0xDEADBEEF
```

### Record 180

- Family / subtype: `Linux` / `Syslog`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Failing assertions: `family_match`, `subtype_match`
- Triage: `heuristic_limit`
- Outcome: No ATT&CK mapping produced for this Linux log; handled gracefully as `no_mapping`. Parser extracted 0 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
Apr 18 03:45:00 srv-linux-01 : %LOG_SYSTEM_FAILURE% error_code=0xDEADBEEF
```

### Record 188

- Family / subtype: `Linux` / `Syslog`
- Intent: `Mixed`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `subtype_match`, `attack_mapping_presence`
- Triage: `corpus_ambiguity`, `heuristic_limit`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:20:00 srv-linux-01 sshd[6020]: Accepted password for root from 10.10.1.10 port 55105 ssh2
```

### Record 189

- Family / subtype: `Linux` / `Syslog`
- Intent: `Mixed`
- Expected technique: `T1040` — actual: `T1040`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: Mapped to `T1040` (Network Sniffing) via rule at confidence 0.78. Parser extracted 7 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:20:10 srv-linux-01 sudo:    j.doe : TTY=pts/0 ; PWD=/home/j.doe ; USER=root ; COMMAND=/usr/bin/tcpdump -i eth0 -w /tmp/out.pcap
```

### Record 190

- Family / subtype: `Linux` / `Syslog`
- Intent: `Mixed`
- Expected technique: `T1548.001` — actual: `T1548`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `subtype_match`
- Triage: `heuristic_limit`
- Outcome: Mapped to `T1548` (Abuse Elevation Control Mechanism) via rule at confidence 0.75. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:20:20 srv-linux-01 sudo:    deploy : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/find / -perm -4000
```

