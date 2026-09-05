# Benign log corpus

This directory holds log lines that a healthy host or device produces during
routine operation. Anything the pipeline maps to an ATT&CK technique here is a
false positive.

## What is in here

- `seed_windows.log`, `seed_linux.log`, `seed_network.log` are **synthetic**.
  They were hand-written so the regression gate has something to run against
  from day one. They are a floor, not a measurement of real-world noise.
- `real/` is where sanitized real logs from lab or personal hosts go. **That is
  the corpus that actually matters** — the seed files only keep the gate honest
  until `real/` has volume.

## Sanitization rules for `real/`

Before committing anything under `real/`:

- Replace public IP addresses with RFC 5737 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). RFC 1918 addresses may
  stay as-is.
- Replace real hostnames, usernames, domains, and email addresses with generic
  ones (`WKS-ACC-011`, `jmalik`, `corp.example.internal`, `example.com`).
- Strip anything covered by an NDA, and anything from an employer or customer
  environment you do not have permission to publish: credentials, tokens, API
  keys, licence keys, file paths that name a real project, ticket IDs.
- Keep one log line per line. Blank lines are skipped by the loader.

If in doubt, leave the line out. The corpus is worth less than a leak.

## How the gate uses this directory

`tests/test_benign_corpus.py` and `scripts/benign_report.py` share one loader
(`scripts.benign_report.collect`). It reads **every `*.log` file under this
directory, recursively** — so dropping a new file into `real/` puts it in the
gate immediately — and runs `src.pipeline.run(line, model=None)` on each
non-empty line individually.

`baseline.json` records the false positives that existed when the baseline was
last taken. The gate fails when a `(file, line, technique_id)` tuple appears
that is not in the baseline, when a strength tier's count goes up, or when
`total_lines` no longer matches the baseline. False positives that *disappear*
never fail a test; they are printed as a notice (visible with `pytest -rP`).

## Updating the baseline

Adding lines to the corpus, or intentionally changing a rule, requires a
baseline refresh. From the repository root:

```
python scripts/benign_report.py --update-baseline
```

Read the report output before committing the new `baseline.json`. Only refresh
when the change in false positives is intentional and understood — refreshing
to make a red build go green defeats the purpose of the gate.
