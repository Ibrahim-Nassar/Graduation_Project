# Failing assertion: attack_mapping_presence

All records whose `attack_mapping_presence` assertion is failing.

_assertion=attack_mapping_presence, failing=18_

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
| 93 | IDS | Zeek JSON | Mixed | — | `T1021` | medium | rule | `attack_mapping_presence` | `corpus_ambiguity` |
| 136 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 137 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 138 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 139 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 184 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 185 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 186 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 187 | Linux | Syslog sshd | Duplicate | — | `T1078` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 188 | Linux | Syslog | Mixed | — | `T1078` | medium | rule | `subtype_match`, `attack_mapping_presence` | `corpus_ambiguity`, `heuristic_limit` |

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

### Record 93

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Mixed`
- Expected technique: — — actual: `T1021`
- Severity: `medium` — mapping source: `rule`
- Failing assertions: `attack_mapping_presence`
- Triage: `corpus_ambiguity`
- Outcome: Mapped to `T1021` (Remote Services) via rule at confidence 0.75. Parser extracted 11 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"ts":1713412010.2,"uid":"X123457","id.orig_h":"10.10.1.10","id.orig_p":49120,"id.resp_h":"198.51.100.200","id.resp_p":3389,"proto":"tcp"...
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

