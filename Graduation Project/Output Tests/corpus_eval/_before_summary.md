# SOC Corpus Evaluation Summary

- Corpus: `soc_synthetic_corpus_192.jsonl`
- Path: `tests\data\soc_synthetic_corpus_192.jsonl`
- Harness version: `corpus-eval-v1`
- Started: 2026-04-18T01:11:07.824239+00:00
- Finished: 2026-04-18T01:11:07.907945+00:00
- Duration: 0.084 s

## Totals

- Total logs evaluated: **192**
- Analyzer OK: **7**
- Analyzer failures (ok=false or exception): **185**
- Mapping sources: rule=7, ml_fallback=0, none=185
- Missing severity values: 0
- Malformed handled gracefully (ok=false, reason=no_mapping): 185
- Unhandled exceptions: 0

## Failures by family

| Family | Total | OK | Failures | No mapping | Exceptions | Malformed handled | With ATT&CK |
|---|---:|---:|---:|---:|---:|---:|---:|
| Firewall | 48 | 0 | 48 | 48 | 0 | 48 | 0 |
| IDS | 48 | 0 | 48 | 48 | 0 | 48 | 0 |
| Linux | 48 | 0 | 48 | 48 | 0 | 48 | 0 |
| Windows | 48 | 7 | 41 | 41 | 0 | 41 | 7 |

## Grouped failure categories

- Malformed handling issues: 0
- Parser misses (wrong family detection): 0
- Normalisation gaps (missing expected entity in parsed output): 14
- Missing ATT&CK mapping when corpus expected one: 99
- Wrong ATT&CK mapping vs corpus expectation: 0

## Top produced techniques

- `T1059`: 5
- `T1053`: 1
- `T1021`: 1

## Top recurring errors

- (185) No ATT&CK mapping could be produced for this log.

## Known architecture observations

- `analyze_soc_log` treats any log that cannot be mapped to a MITRE technique as `ok=False` (reason=`no_mapping`). Benign traffic therefore counts as a "failure" from a harness perspective even though the handling is correct. Inspect `mapping_sources.none` and the corpus `map_none` expectation for a truer signal.
- Family/subtype detection in the current codebase is inferred heuristically; the harness records both the corpus-provided family and a best-effort detected family, but the application itself does not carry an explicit family classifier.
- Verdict/classification beyond ATT&CK + severity is limited; `verdict` in the harness reflects the coarse `ok` / `no_mapping` / `error` state of `analyze_soc_log`.

> Expected-vs-actual strict assertions are deliberately left as a future step;
> all expected labels are already carried on each record for that work.
