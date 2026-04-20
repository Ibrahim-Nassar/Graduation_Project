# Family: Firewall

All records whose expected family is `Firewall`.

_family=Firewall, size=48_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 0 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 1 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 2 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 3 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 4 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 5 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 6 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 7 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 8 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 9 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 10 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 11 | Firewall | Fortinet KV | Benign | — | — | info | none | — | — |
| 12 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 13 | Firewall | Fortinet KV | Suspicious | `T1595` | `T1595` | medium | rule | — | — |
| 14 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 15 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 16 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 17 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 18 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 19 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 20 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 21 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 22 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 23 | Firewall | Fortinet KV | Suspicious | `T1071.001` | `T1071` | medium | rule | — | — |
| 24 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 25 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 26 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 27 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 28 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 29 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 30 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 31 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 32 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 33 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 34 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 35 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 36 | Firewall | Fortinet KV | Malformed | — | — | info | none | — | — |
| 37 | Firewall | Fortinet KV | Malformed | — | — | info | none | — | — |
| 38 | Firewall | Fortinet KV | Malformed | — | — | info | none | — | — |
| 39 | Firewall | Fortinet KV | Malformed | — | — | info | none | — | — |
| 40 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 41 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 42 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 43 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 44 | Firewall | Fortinet KV | Mixed | `T1021.004` | `T1021` | medium | rule | — | — |
| 45 | Firewall | Fortinet KV | Mixed | `T1021.001` | `T1021` | medium | rule | — | — |
| 46 | Firewall | Fortinet KV | Mixed | — | — | info | none | — | — |
| 47 | Firewall | Fortinet KV | Mixed | — | — | info | none | — | — |

## Records

### Record 0

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:01 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 1

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:06 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 2

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:11 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 3

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:16 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 4

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:21 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 5

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:26 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 6

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:31 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 7

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:36 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 8

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:41 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 9

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:46 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 10

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:51 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 11

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Benign`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 11 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:00:56 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 12

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:00 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 13

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1595` — actual: `T1595`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1595` (Active Scanning) via rule at confidence 0.7. Parser extracted 11 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:05 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 14

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:10 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 15

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:15 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 16

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:20 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 17

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:25 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 18

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:30 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 19

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:35 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 20

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:40 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 21

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:45 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 22

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:50 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 23

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Suspicious`
- Expected technique: `T1071.001` — actual: `T1071`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1071` (Application Layer Protocol) via rule at confidence 0.78. Parser extracted 12 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:05:55 devname="FW-CORE-01" devid="FGT60E-SEC-99" logid="0000000013" type="traffic" subtype="forward" srcip=10.10....
```

### Record 24

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:00 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 25

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:05 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 26

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:10 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 27

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:15 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 28

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:20 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 29

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:25 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 30

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:30 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 31

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:35 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 32

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:40 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 33

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:45 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 34

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:50 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 35

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:55 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
```

### Record 36

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 3 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:15:00 devname= srcip=10.10.25.10 dstip=198.51.100.1 bytes=ERR
```

### Record 37

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 4 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:15:05 srcip=10.10.25.10 dstip= dstport=0 action=accept
```

### Record 38

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 5 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:15:10 devname="FW-CORE-01" srcip=10.10.25.10 dstip=198.51.100.1 sentbyte=NaN rcvdbyte=NaN
```

### Record 39

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malformed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 3 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=9999-99-99 time=99:99:99 devname="FW-CORE-01" srcip=256.256.256.256 dstip=10.10.10.10
```

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

### Record 44

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Mixed`
- Expected technique: `T1021.004` — actual: `T1021`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1021` (Remote Services) via rule at confidence 0.75. Parser extracted 9 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:20:00 devname="FW-CORE-01" srcip=10.10.1.10 dstip=10.10.100.5 dstport=22 action="accept" service="SSH" duration=3...
```

### Record 45

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Mixed`
- Expected technique: `T1021.001` — actual: `T1021`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1021` (Remote Services) via rule at confidence 0.75. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:20:10 devname="FW-CORE-01" srcip=10.10.1.10 dstip=198.51.100.200 dstport=3389 action="accept" service="RDP" sentb...
```

### Record 46

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Mixed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 8 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:20:20 devname="FW-CORE-01" srcip=10.10.25.5 dstip=10.10.10.100 dstport=80 action="accept" service="HTTP" sentbyte...
```

### Record 47

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Mixed`
- Expected technique: — — actual: —
- Severity: `info` — mapping source: `none`
- Outcome: No ATT&CK mapping produced for this Firewall log; handled gracefully as `no_mapping`. Parser extracted 8 normalized field(s); 0 mapping evidence ref(s); severity `info`.

```
date=2026-04-18 time=03:20:30 devname="FW-CORE-01" srcip=10.10.25.10 dstip=198.51.100.10 dstport=443 action="accept" service="HTTPS" sent...
```

