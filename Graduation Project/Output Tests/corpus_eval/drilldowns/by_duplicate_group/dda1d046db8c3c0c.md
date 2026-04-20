# Duplicate group: dda1d046db8c3c0c

All records whose normalised signature matches this near-duplicate cluster (`dda1d046db8c3c0c`).

_signature=dda1d046db8c3c0c, size=10_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 24 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 27 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 29 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 31 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 34 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 35 | Firewall | Fortinet KV | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 40 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 41 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 42 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 43 | Firewall | Fortinet KV | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |

## Records

### Record 24

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:00 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
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

### Record 29

- Family / subtype: `Firewall` / `Fortinet KV`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 8 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
date=2026-04-18 time=03:10:25 devname="FW-CORE-01" logid="0000000013" type="traffic" srcip=10.10.50.22 dstip=198.51.100.150 dstport=443 a...
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

