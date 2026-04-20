# SOC Corpus Evaluation Summary

- Corpus: `soc_synthetic_corpus_192.jsonl`
- Path: `tests\data\soc_synthetic_corpus_192.jsonl`
- Harness version: `corpus-eval-v3`
- Started: 2026-04-18T02:17:09.020518+00:00
- Finished: 2026-04-18T02:17:09.137037+00:00
- Duration: 0.117 s

## Executive summary

- **120/192 logs** pass the production pipeline end-to-end (0 unhandled exceptions).
- **164/192 records** satisfy every strict assertion (28 have at least one failing assertion).
- **1269 assertions pass, 30 fail** across 1728 total assertions.
- Triage of failing assertions: **0 product defect(s)**, 11 evaluator-heuristic limit(s), 19 corpus-ambiguity / label conflict(s).
- Baseline delta: **0 newly passing / 0 newly failing** assertions vs prior snapshot.

## Pipeline health by family

| Family | Total | OK | Exceptions | With ATT&CK | Assert pass | Assert fail |
|---|---:|---:|---:|---:|---:|---:|
| Firewall | 48 | 30 | 0 | 30 | 337 | 4 |
| IDS | 48 | 29 | 0 | 29 | 340 | 5 |
| Linux | 48 | 31 | 0 | 31 | 279 | 16 |
| Windows | 48 | 30 | 0 | 30 | 313 | 5 |

## Totals

- Total logs evaluated: **192**
- Analyzer OK: **120**
- Analyzer failures (ok=false or exception): **72**
- Mapping sources: rule=120, ml_fallback=0, none=72
- Missing severity values: 0
- Malformed handled gracefully (ok=false, reason=no_mapping): 72
- Unhandled exceptions: 0

## Failures by family

| Family | Total | OK | Failures | No mapping | Exceptions | Malformed handled | With ATT&CK |
|---|---:|---:|---:|---:|---:|---:|---:|
| Firewall | 48 | 30 | 18 | 18 | 0 | 18 | 30 |
| IDS | 48 | 29 | 19 | 19 | 0 | 19 | 29 |
| Linux | 48 | 31 | 17 | 17 | 0 | 17 | 31 |
| Windows | 48 | 30 | 18 | 18 | 0 | 18 | 30 |

## Grouped failure categories

- Malformed handling issues: 0
- Parser misses (wrong family detection): 0
- Normalisation gaps (missing expected entity in parsed output): 0
- Missing ATT&CK mapping when corpus expected one: 0
- Wrong ATT&CK mapping vs corpus expectation: 1

## Top produced techniques

- `T1041`: 32
- `T1071`: 22
- `T1110`: 12
- `T1059`: 8
- `T1078`: 6
- `T1021`: 4
- `T1552`: 4
- `T1003`: 3
- `T1595`: 2
- `T1033`: 2

## Top recurring errors

- (72) No ATT&CK mapping could be produced for this log.

## Expected-vs-actual assertions

- Total records evaluated: 192
- Records with every assertion passing: 164
- Records with at least one failing assertion: 28
- Malformed-handling failures: 0

### Assertions by name

| Assertion | Pass | Partial | Fail | Skip |
|---|---:|---:|---:|---:|
| `attack_mapping_presence` | 174 | 0 | 18 | 0 |
| `attack_technique_match` | 42 | 59 | 1 | 90 |
| `expected_entities_present` | 104 | 0 | 0 | 88 |
| `expected_fields_present` | 176 | 0 | 0 | 16 |
| `family_match` | 191 | 0 | 1 | 0 |
| `malformed_handling` | 16 | 0 | 0 | 176 |
| `no_unhandled_exception` | 192 | 0 | 0 | 0 |
| `severity_presence` | 192 | 0 | 0 | 0 |
| `subtype_match` | 182 | 0 | 10 | 0 |

### Assertions by family

| Family | Pass | Partial | Fail | Skip |
|---|---:|---:|---:|---:|
| Firewall | 337 | 13 | 4 | 78 |
| IDS | 340 | 11 | 5 | 76 |
| Linux | 279 | 23 | 16 | 114 |
| Windows | 313 | 12 | 5 | 102 |

### Top ATT&CK mismatches

| Expected | Actual | Count |
|---|---|---:|
| `T1083` | `T1552` | 1 |

## Failure triage

Every failing assertion has been classified into one of six triage categories so that true product defects are separated from corpus ambiguity and harness-side heuristic limits.

### Failures by triage category

| Category | Count |
|---|---:|
| `heuristic_limit` | 11 |
| `expected_label_conflict` | 17 |
| `corpus_ambiguity` | 2 |

### Recommended fix targets

- `evaluator_logic`: 11
- `corpus_labels`: 19

### Failure clusters (by group key)

| Group | Category | Fix target | Count | Sample reason |
|---|---|---|---:|---|
| `subtype_match:Syslog->Syslog sshd` | `heuristic_limit` | `evaluator_logic` | 5 | harness subtype heuristic cannot distinguish these shapes |
| `map_none_conflict:dda1d046db8c3c0c` | `expected_label_conflict` | `corpus_labels` | 4 | duplicate/near-duplicate logs disagree on whether this traffic shape should be mapped |
| `map_none_conflict:2d4fbdabef459f30` | `expected_label_conflict` | `corpus_labels` | 4 | duplicate/near-duplicate logs disagree on whether this traffic shape should be mapped |
| `map_none_conflict:dfe935522db806e2` | `expected_label_conflict` | `corpus_labels` | 4 | duplicate/near-duplicate logs disagree on whether this traffic shape should be mapped |
| `subtype_match:Syslog->Syslog sudo` | `heuristic_limit` | `evaluator_logic` | 4 | harness subtype heuristic cannot distinguish these shapes |
| `map_none_conflict:68453c4a1108df9f` | `expected_label_conflict` | `corpus_labels` | 4 | duplicate/near-duplicate logs disagree on whether this traffic shape should be mapped |
| `unexpected_mapping:T1021` | `corpus_ambiguity` | `corpus_labels` | 1 | corpus expects no mapping but the traffic pattern justifies one (content-identical duplicate intent in the corpus) |
| `technique_conflict:8337282864820a02` | `expected_label_conflict` | `corpus_labels` | 1 | duplicate/near-duplicate logs carry different expected ATT&CK techniques for the same shape |
| `family_match:none` | `heuristic_limit` | `evaluator_logic` | 1 | harness family heuristic returned None |
| `subtype_match:Syslog->None` | `heuristic_limit` | `evaluator_logic` | 1 | harness subtype heuristic cannot distinguish these shapes |
| `unexpected_mapping:T1078` | `corpus_ambiguity` | `corpus_labels` | 1 | corpus expects no mapping but the traffic pattern justifies one (content-identical duplicate intent in the corpus) |

## Corpus duplicates and label conflicts

- Exact-duplicate groups: 4
- Near-duplicate groups: 14
- Groups with conflicting expectations: **5**

The following groups contain logs whose surface content is materially identical but whose corpus metadata carries different expectations. These are the root cause of the ``expected_label_conflict`` failures reported above.

| Signature | Size | Conflicting keys | Indices | Sample |
|---|---:|---|---|---|
| `dda1d046db8c3c0c` | 10 | expected_attack_mapping, expected_map_none | 24, 27, 29, 31, 34, 35 | date=2026-04-18 time=03:10:00 devname="FW-CORE-01" logid="0000000013" type="traf |
| `2d4fbdabef459f30` | 5 | expected_attack_mapping, expected_map_none | 72, 88, 89, 90, 91 | {"ts":1713410000.0,"uid":"M1029381","id.orig_h":"10.10.50.22","id.orig_p":54001, |
| `68453c4a1108df9f` | 5 | expected_attack_mapping, expected_map_none | 168, 184, 185, 186, 187 | Apr 18 03:10:00 srv-linux-01 sshd[5010]: Accepted password for root from 198.51. |
| `dfe935522db806e2` | 5 | expected_attack_mapping, expected_map_none | 120, 136, 137, 138, 139 | {"@timestamp":"2026-04-18T03:10:00.001Z","winlog":{"event_id":"4688","event_data |
| `8337282864820a02` | 2 | expected_attack_mapping | 118, 130 | {"@timestamp":"2026-04-18T03:06:40.001Z","winlog":{"event_id":"4688","event_data |

## Top mapping weaknesses

| Expected | Actual | Count |
|---|---|---:|
| `T1083` | `T1552` | 1 |

- Records where the produced technique disagrees with the corpus: **1**

## Malformed-log behaviour

- Logs gracefully handled with `ok=false` + `reason=no_mapping`: **72**
- Malformed-handling assertion failures (silent acceptance / crash): **0**

## Regression status (vs baseline)

- Unchanged records: 192
- Newly failing assertions: 0
- Newly passing assertions: 0

## Recommended next engineering steps

Ordered by leverage: product defects first, then harness / evaluator improvements, then corpus-label conflicts that need analyst review.

- **heuristic_limit** (`evaluator_logic`) — `subtype_match:Syslog->Syslog sshd` ×5 — harness subtype heuristic cannot distinguish these shapes
- **heuristic_limit** (`evaluator_logic`) — `subtype_match:Syslog->Syslog sudo` ×4 — harness subtype heuristic cannot distinguish these shapes
- **heuristic_limit** (`evaluator_logic`) — `family_match:none` ×1 — harness family heuristic returned None
- **heuristic_limit** (`evaluator_logic`) — `subtype_match:Syslog->None` ×1 — harness subtype heuristic cannot distinguish these shapes
- **expected_label_conflict** (`corpus_labels`) — `map_none_conflict:dda1d046db8c3c0c` ×4 — duplicate/near-duplicate logs disagree on whether this traffic shape should be mapped
- **expected_label_conflict** (`corpus_labels`) — `map_none_conflict:2d4fbdabef459f30` ×4 — duplicate/near-duplicate logs disagree on whether this traffic shape should be mapped
- **expected_label_conflict** (`corpus_labels`) — `map_none_conflict:dfe935522db806e2` ×4 — duplicate/near-duplicate logs disagree on whether this traffic shape should be mapped
- **expected_label_conflict** (`corpus_labels`) — `map_none_conflict:68453c4a1108df9f` ×4 — duplicate/near-duplicate logs disagree on whether this traffic shape should be mapped
- **expected_label_conflict** (`corpus_labels`) — `technique_conflict:8337282864820a02` ×1 — duplicate/near-duplicate logs carry different expected ATT&CK techniques for the same shape
- **corpus_ambiguity** (`corpus_labels`) — `unexpected_mapping:T1021` ×1 — corpus expects no mapping but the traffic pattern justifies one (content-identical duplicate intent in the corpus)

## Known architecture observations

- `analyze_soc_log` treats any log that cannot be mapped to a MITRE technique as `ok=False` (reason=`no_mapping`). Benign traffic therefore counts as a "failure" from a harness perspective even though the handling is correct. Inspect `mapping_sources.none` and the corpus `map_none` expectation for a truer signal.
- Family/subtype detection in the current codebase is inferred heuristically; the harness records both the corpus-provided family and a best-effort detected family, but the application itself does not carry an explicit family classifier.
- Verdict/classification beyond ATT&CK + severity is limited; `verdict` in the harness reflects the coarse `ok` / `no_mapping` / `error` state of `analyze_soc_log`.

