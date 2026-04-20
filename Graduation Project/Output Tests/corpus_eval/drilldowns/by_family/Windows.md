# Family: Windows

All records whose expected family is `Windows`.

_family=Windows, size=48_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 96 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 97 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 98 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 99 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 100 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 101 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 102 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 103 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 104 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 105 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 106 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 107 | Windows | Winlogbeat JSON | Benign | — | — | info | none | — | — |
| 108 | Windows | Winlogbeat JSON | Suspicious | `T1059.001` | `T1059` | high | rule | — | — |
| 109 | Windows | Winlogbeat JSON | Suspicious | `T1033` | `T1033` | medium | rule | — | — |
| 110 | Windows | Winlogbeat JSON | Suspicious | `T1087.002` | `T1087` | medium | rule | — | — |
| 111 | Windows | Winlogbeat JSON | Suspicious | `T1016` | `T1016` | medium | rule | — | — |
| 112 | Windows | Winlogbeat JSON | Suspicious | `T1482` | `T1482` | medium | rule | — | — |
| 113 | Windows | Winlogbeat JSON | Suspicious | `T1033` | `T1033` | medium | rule | — | — |
| 114 | Windows | Winlogbeat JSON | Suspicious | `T1057` | `T1057` | medium | rule | — | — |
| 115 | Windows | Winlogbeat JSON | Suspicious | `T1082` | `T1082` | medium | rule | — | — |
| 116 | Windows | Winlogbeat JSON | Suspicious | `T1087.002` | `T1087` | medium | rule | — | — |
| 117 | Windows | Winlogbeat JSON | Suspicious | `T1016` | `T1016` | medium | rule | — | — |
| 118 | Windows | Winlogbeat JSON | Suspicious | `T1552.001` | `T1552` | medium | rule | — | — |
| 119 | Windows | Winlogbeat JSON | Suspicious | `T1012` | `T1012` | medium | rule | — | — |
| 120 | Windows | Winlogbeat JSON | Malicious | `T1059.001` | `T1059` | high | rule | — | — |
| 121 | Windows | Winlogbeat JSON | Malicious | `T1053.005` | `T1053` | high | rule | — | — |
| 122 | Windows | Winlogbeat JSON | Malicious | `T1218.011` | `T1218` | medium | rule | — | — |
| 123 | Windows | Winlogbeat JSON | Malicious | `T1105` | `T1105` | medium | rule | — | — |
| 124 | Windows | Winlogbeat JSON | Malicious | `T1204.002` | `T1204` | medium | rule | — | — |
| 125 | Windows | Winlogbeat JSON | Malicious | `T1490` | `T1490` | medium | rule | — | — |
| 126 | Windows | Winlogbeat JSON | Malicious | `T1490` | `T1490` | medium | rule | — | — |
| 127 | Windows | Winlogbeat JSON | Malicious | `T1197` | `T1197` | medium | rule | — | — |
| 128 | Windows | Winlogbeat JSON | Malicious | `T1003.003` | `T1003` | critical | rule | — | — |
| 129 | Windows | Winlogbeat JSON | Malicious | `T1003.003` | `T1003` | critical | rule | — | — |
| 130 | Windows | Winlogbeat JSON | Malicious | `T1083` | `T1552` | medium | rule | `attack_technique_match` | `expected_label_conflict` |
| 131 | Windows | Winlogbeat JSON | Malicious | `T1562.001` | `T1562` | medium | rule | — | — |
| 132 | Windows | Winlogbeat JSON | Malformed | — | — | info | none | — | — |
| 133 | Windows | Winlogbeat JSON | Malformed | — | — | info | none | — | — |
| 134 | Windows | Winlogbeat JSON | Malformed | — | — | info | none | — | — |
| 135 | Windows | Winlogbeat JSON | Malformed | — | — | info | none | — | — |
| 136 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 137 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 138 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 139 | Windows | Winlogbeat JSON | Duplicate | — | `T1059` | high | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 140 | Windows | Winlogbeat JSON | Mixed | `T1047` | `T1047` | medium | rule | — | — |
| 141 | Windows | Winlogbeat JSON | Mixed | — | — | info | none | — | — |
| 142 | Windows | Winlogbeat JSON | Mixed | — | — | info | none | — | — |
| 143 | Windows | Winlogbeat JSON | Mixed | `T1021.001` | `T1021` | medium | rule | — | — |

## Records

### Record 96

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 7 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:00.001Z","winlog":{"event_id":"4624","event_data":{"TargetUserName":"j.doe","LogonType":"2","TargetDomain...
```

### Record 97

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:05.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\notepad.exe",...
```

### Record 98

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:10.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Program Files\\Google\\Chrome\\A...
```

### Record 99

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 6 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:15.001Z","winlog":{"event_id":"4624","event_data":{"TargetUserName":"SYSTEM","LogonType":"5","TargetDomai...
```

### Record 100

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:20.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\taskhostw.exe...
```

### Record 101

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:25.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\SearchIndexer...
```

### Record 102

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 7 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:30.001Z","winlog":{"event_id":"4624","event_data":{"TargetUserName":"j.doe","LogonType":"3","TargetDomain...
```

### Record 103

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:35.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\smartscreen.e...
```

### Record 104

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:40.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\conhost.exe",...
```

### Record 105

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 6 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:45.001Z","winlog":{"event_id":"4624","event_data":{"TargetUserName":"LOCAL SERVICE","LogonType":"5","Targ...
```

### Record 106

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:50.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\dllhost.exe",...
```

### Record 107

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:00:55.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\audiodg.exe",...
```

### Record 108

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1059.001` — actual: `T1059`
- Severity: `high` — mapping source: `rule`
- Outcome: Mapped to `T1059` (Command and Scripting Interpreter) via rule at confidence 0.82. Parser extracted 5 normalized field(s); 2 mapping evidence ref(s); severity `high`.

```
{"@timestamp":"2026-04-18T03:05:00.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\WindowsPowerS...
```

### Record 109

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1033` — actual: `T1033`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1033` (System Owner/User Discovery) via rule at confidence 0.72. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:05:10.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\whoami.exe","...
```

### Record 110

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1087.002` — actual: `T1087`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1087` (Account Discovery) via rule at confidence 0.75. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:05:20.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\net.exe","Com...
```

### Record 111

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1016` — actual: `T1016`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1016` (System Network Configuration Discovery) via rule at confidence 0.72. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:05:30.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\ipconfig.exe"...
```

### Record 112

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1482` — actual: `T1482`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1482` (Domain Trust Discovery) via rule at confidence 0.78. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:05:40.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\nltest.exe","...
```

### Record 113

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1033` — actual: `T1033`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1033` (System Owner/User Discovery) via rule at confidence 0.72. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:05:50.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\quser.exe","C...
```

### Record 114

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1057` — actual: `T1057`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1057` (Process Discovery) via rule at confidence 0.7. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:06:00.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\tasklist.exe"...
```

### Record 115

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1082` — actual: `T1082`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1082` (System Information Discovery) via rule at confidence 0.72. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:06:10.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\systeminfo.ex...
```

### Record 116

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1087.002` — actual: `T1087`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1087` (Account Discovery) via rule at confidence 0.75. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:06:20.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\net.exe","Com...
```

### Record 117

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1016` — actual: `T1016`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1016` (System Network Configuration Discovery) via rule at confidence 0.72. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:06:30.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\nslookup.exe"...
```

### Record 118

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1552.001` — actual: `T1552`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1552` (Unsecured Credentials) via rule at confidence 0.8. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:06:40.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\findstr.exe",...
```

### Record 119

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Suspicious`
- Expected technique: `T1012` — actual: `T1012`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1012` (Query Registry) via rule at confidence 0.72. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:06:50.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\reg.exe","Com...
```

### Record 120

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1059.001` — actual: `T1059`
- Severity: `high` — mapping source: `rule`
- Outcome: Mapped to `T1059` (Command and Scripting Interpreter) via rule at confidence 0.9. Parser extracted 5 normalized field(s); 2 mapping evidence ref(s); severity `high`.

```
{"@timestamp":"2026-04-18T03:10:00.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\cmd.exe","Com...
```

### Record 121

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1053.005` — actual: `T1053`
- Severity: `high` — mapping source: `rule`
- Outcome: Mapped to `T1053` (Scheduled Task/Job) via rule at confidence 0.85. Parser extracted 5 normalized field(s); 2 mapping evidence ref(s); severity `high`.

```
{"@timestamp":"2026-04-18T03:10:05.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\schtasks.exe"...
```

### Record 122

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1218.011` — actual: `T1218`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1218` (System Binary Proxy Execution) via rule at confidence 0.82. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:10:10.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\rundll32.exe"...
```

### Record 123

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1105` — actual: `T1105`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1105` (Ingress Tool Transfer) via rule at confidence 0.85. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:10:15.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\certutil.exe"...
```

### Record 124

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1204.002` — actual: `T1204`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1204` (User Execution) via rule at confidence 0.65. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:10:20.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Users\\Public\\payload.exe","Com...
```

### Record 125

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1490` — actual: `T1490`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1490` (Inhibit System Recovery) via rule at confidence 0.9. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:10:25.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\wbem\\wmic.ex...
```

### Record 126

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1490` — actual: `T1490`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1490` (Inhibit System Recovery) via rule at confidence 0.9. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:10:30.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\vssadmin.exe"...
```

### Record 127

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1197` — actual: `T1197`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1197` (BITS Jobs) via rule at confidence 0.85. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:10:35.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\bitsadmin.exe...
```

### Record 128

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1003.003` — actual: `T1003`
- Severity: `critical` — mapping source: `rule`
- Outcome: Mapped to `T1003` (OS Credential Dumping) via rule at confidence 0.85. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `critical`.

```
{"@timestamp":"2026-04-18T03:10:40.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\ntdsutil.exe"...
```

### Record 129

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1003.003` — actual: `T1003`
- Severity: `critical` — mapping source: `rule`
- Outcome: Mapped to `T1003` (OS Credential Dumping) via rule at confidence 0.88. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `critical`.

```
{"@timestamp":"2026-04-18T03:10:45.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\esentutl.exe"...
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

### Record 131

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malicious`
- Expected technique: `T1562.001` — actual: `T1562`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1562` (Impair Defenses) via rule at confidence 0.85. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:10:55.001Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\net.exe","Com...
```

### Record 132

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 1 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"NULL","winlog":{"event_id":4624,"event_data":{"TargetUserName":{}}}}
```

### Record 133

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 2 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:15:00Z","winlog":{"event_id":"ERR","event_data":{"ProcessName":"\\.\\PhysicalDrive0"}}}
```

### Record 134

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 2 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-13-45T25:00:00Z","winlog":{"event_id":"4688"}}
```

### Record 135

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 2 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:15:10Z","winlog":{"event_id":"4688","event_data":{"CommandLine":[1,2,3]}}}
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

### Record 140

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Mixed`
- Expected technique: `T1047` — actual: `T1047`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1047` (Windows Management Instrumentation) via rule at confidence 0.82. Parser extracted 5 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:20:00Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\wbem\\WMIC.exe","...
```

### Record 141

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Mixed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:20:10Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell...
```

### Record 142

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Mixed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Windows log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
{"@timestamp":"2026-04-18T03:20:20Z","winlog":{"event_id":"4624","event_data":{"TargetUserName":"admin_service","LogonType":"2","IpAddres...
```

### Record 143

- Family / subtype: `Windows` / `Winlogbeat JSON`
- Intent: `Mixed`
- Expected technique: `T1021.001` — actual: `T1021`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1021` (Remote Services) via rule at confidence 0.82. Parser extracted 6 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"@timestamp":"2026-04-18T03:20:30Z","winlog":{"event_id":"4688","event_data":{"NewProcessName":"C:\\Windows\\System32\\mstsc.exe","Comma...
```

