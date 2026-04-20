# Triage: corpus_ambiguity

All failing assertions classified as `corpus_ambiguity`.

_category=corpus_ambiguity, size=2_

| # | Family | Subtype | Intent | Expected | Actual | Severity | Source | Failing | Triage |
|---:|---|---|---|---|---|---|---|---|---|
| 93 | IDS | Zeek JSON | Mixed | — | `T1021` | medium | rule | `attack_mapping_presence` | `corpus_ambiguity` |
| 188 | Linux | Syslog | Mixed | — | `T1078` | medium | rule | `subtype_match`, `attack_mapping_presence` | `corpus_ambiguity`, `heuristic_limit` |

## Records

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

