# Triage: expected_label_conflict

All failing assertions classified as `expected_label_conflict`.

_category=expected_label_conflict, size=17_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 40 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 41 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 42 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 43 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 88 | IDS | Zeek JSON | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 89 | IDS | Zeek JSON | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 90 | IDS | Zeek JSON | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 91 | IDS | Zeek JSON | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 130 | Windows | Winlogbeat JSON | Malicious | `T1083` | `T1552` | medium | rule | `attack_technique_match` | `expected_label_conflict` |
| 136 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 137 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 138 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 139 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 184 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 185 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 186 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 187 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |

## Records

### Record 40

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:00 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 41

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:00 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 42

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:00 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 43

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:00 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 88

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 11 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"ts":1713410000.15,"uid":"M1029381","id.orig_h":"10.10.50.22","id.orig_p":54001,"id.resp_h":"198.51.100.150","id.resp_p":443,"proto":"tc...
```

### Record 89

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 11 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"ts":1713410000.15,"uid":"M1029381","id.orig_h":"10.10.50.22","id.orig_p":54001,"id.resp_h":"198.51.100.150","id.resp_p":443,"proto":"tc...
```

### Record 90

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 11 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"ts":1713410000.15,"uid":"M1029381","id.orig_h":"10.10.50.22","id.orig_p":54001,"id.resp_h":"198.51.100.150","id.resp_p":443,"proto":"tc...
```

### Record 91

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 11 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"ts":1713410000.15,"uid":"M1029381","id.orig_h":"10.10.50.22","id.orig_p":54001,"id.resp_h":"198.51.100.150","id.resp_p":443,"proto":"tc...
```

### Record 130

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1083` — actual: `T1552`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_technique_match`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1552` (Unsecured Credentials) via rule at confidence 0.8. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:10:50.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\findstr.exe",...
```

### Record 136

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1059`
- Severity: `high` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1059` (Command and Scripting Interpreter) via rule at confidence 0.9. Parser extracted 5 normalized field(s); 2 mapping evidence ref(s); severity `high`.

```
{"@timestamp":"2026-04-18T03:10:00.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\cmd.exe","Com...
```

### Record 137

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1059`
- Severity: `high` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1059` (Command and Scripting Interpreter) via rule at confidence 0.9. Parser extracted 5 normalized field(s); 2 mapping evidence ref(s); severity `high`.

```
{"@timestamp":"2026-04-18T03:10:00.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\cmd.exe","Com...
```

### Record 138

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1059`
- Severity: `high` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1059` (Command and Scripting Interpreter) via rule at confidence 0.9. Parser extracted 5 normalized field(s); 2 mapping evidence ref(s); severity `high`.

```
{"@timestamp":"2026-04-18T03:10:00.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\cmd.exe","Com...
```

### Record 139

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1059`
- Severity: `high` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1059` (Command and Scripting Interpreter) via rule at confidence 0.9. Parser extracted 5 normalized field(s); 2 mapping evidence ref(s); severity `high`.

```
{"@timestamp":"2026-04-18T03:10:00.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\cmd.exe","Com...
```

### Record 184

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51.100.45 port 54100 ssh2
```

### Record 185

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51.100.45 port 54100 ssh2
```

### Record 186

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51.100.45 port 54100 ssh2
```

### Record 187

- Family / subtype: `Linux` / `Syslog sshd`
- Intent: `Duplicate`
- Expected technique: — — actual: `T1078`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `expected_label_conflict`
- Outcome: Mapped to `T1078` (Valid Accounts) via rule at confidence 0.7. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51.100.45 port 54100 ssh2
```

