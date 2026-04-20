# Failing assertion: family_match

All records whose `family_match` assertion is failing.

_assertion=family_match, failing=1_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 180 | Linux | Syslog | Malformed | — | — | info | none | `family_match`, `subtype_match` | `heuristic_limit` |

## Records

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

