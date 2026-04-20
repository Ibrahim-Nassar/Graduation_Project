# Duplicate group: 2d4fbdabef459f30

All records whose normalised signature matches this near-duplicate cluster (`2d4fbdabef459f30`).

_signature=2d4fbdabef459f30, size=5_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 72 | IDS | Zeek JSON | Malicious | `T1041` | `T1041` | medium | rule | — | — |
| 88 | IDS | Zeek JSON | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 89 | IDS | Zeek JSON | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 90 | IDS | Zeek JSON | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |
| 91 | IDS | Zeek JSON | Duplicate | — | `T1041` | medium | rule | `attack_mapping_presence` | `expected_label_conflict` |

## Records

### Record 72

- Family / subtype: `IDS` / `Zeek JSON`
- Intent: `Malicious`
- Expected technique: `T1041` — actual: `T1041`
- Severity: `medium` — mapping source: `rule`
- Outcome: Mapped to `T1041` (Exfiltration Over C2 Channel) via rule at confidence 0.82. Parser extracted 11 normalized field(s); 1 mapping evidence ref(s); severity `medium`.

```
{"ts":1713410000.0,"uid":"M1029381","id.orig_h":"10.10.50.22","id.orig_p":54001,"id.resp_h":"198.51.100.150","id.resp_p":443,"proto":"tcp...
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

