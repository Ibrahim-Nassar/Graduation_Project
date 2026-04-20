# Failing assertion: attack_technique_match

All records whose `attack_technique_match` assertion is failing.

_assertion=attack_technique_match, failing=1_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 130 | Windows | Winlogbeat JSON | Malicious | `T1083` | `T1552` | medium | rule | `attack_technique_match` | `expected_label_conflict` |

## Records

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

