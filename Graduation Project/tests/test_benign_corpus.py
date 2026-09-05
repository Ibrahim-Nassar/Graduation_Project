"""Regression gate over the benign log corpus.

Every mapping the pipeline produces on ``tests/data/benign/`` is a false
positive: the corpus only contains traffic a healthy host or device produces
during routine operation.  ``baseline.json`` records the false positives that
existed when the baseline was last taken; these tests fail when a *new* one
appears.

The loader is shared with ``scripts/benign_report.py`` -- both the report and
the gate call ``collect()`` from there, so they can never disagree about what
the corpus contains.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.benign_report import (  # noqa: E402  (needs REPO_ROOT on sys.path)
    STRENGTH_ORDER,
    collect,
    load_baseline,
)

REFRESH_HINT = (
    "run `python scripts/benign_report.py --update-baseline` "
    "only if this regression is intentional"
)

_COLLECTION = collect()
_BASELINE = load_baseline()
_BASELINE_KEYS = {
    (entry["file"], entry["line"], entry["technique_id"])
    for entry in _BASELINE["findings"]
}


class BenignCorpusTests(unittest.TestCase):
    def test_no_exceptions(self) -> None:
        if not _COLLECTION.errors:
            return
        details = []
        for error in _COLLECTION.errors:
            details.append(
                f"\n  {error.file}:{error.line}\n"
                f"    line: {error.raw[:200]}\n"
                f"    {error.traceback_text.rstrip()}"
            )
        self.fail(
            f"{len(_COLLECTION.errors)} benign line(s) raised inside the pipeline:"
            + "".join(details)
        )

    def test_no_new_false_positives(self) -> None:
        new_findings = [
            finding for finding in _COLLECTION.findings if finding.key() not in _BASELINE_KEYS
        ]

        removed_keys = sorted(
            _BASELINE_KEYS - {finding.key() for finding in _COLLECTION.findings}
        )
        if removed_keys:
            # Fewer false positives is an improvement, never a failure.  Surface
            # it so the baseline can be refreshed deliberately; `pytest -rP`
            # shows this on a passing run.
            print(
                f"NOTICE: {len(removed_keys)} baseline false positive(s) no longer fire. "
                "Refresh the baseline with "
                "`python scripts/benign_report.py --update-baseline` to lock the "
                "improvement in:"
            )
            for file_name, line_number, technique_id in removed_keys:
                print(f"  - {file_name}:{line_number} {technique_id}")

        if not new_findings:
            return

        details = []
        for finding in new_findings:
            details.append(
                f"\n  ({finding.file}, {finding.line}, {finding.technique_id})"
                f" [{finding.evidence_strength}]\n"
                f"    line: {finding.raw}\n"
                f"    rationale: {finding.rationale}"
            )
        self.fail(
            f"{len(new_findings)} new false positive(s) on the benign corpus "
            f"that are not in baseline.json:"
            + "".join(details)
            + f"\n\n{REFRESH_HINT}."
        )

    def test_strength_counts_do_not_increase(self) -> None:
        baseline_counts = _BASELINE["counts_by_strength"]
        current_counts = _COLLECTION.counts_by_strength
        tiers = list(STRENGTH_ORDER)
        for tier in list(baseline_counts) + list(current_counts):
            if tier not in tiers:
                tiers.append(tier)
        for tier in tiers:
            baseline_count = baseline_counts.get(tier, 0)
            current_count = current_counts.get(tier, 0)
            with self.subTest(evidence_strength=tier):
                self.assertLessEqual(
                    current_count,
                    baseline_count,
                    f"evidence_strength '{tier}' rose from {baseline_count} to "
                    f"{current_count} on the benign corpus; {REFRESH_HINT}",
                )

    def test_baseline_is_current(self) -> None:
        self.assertEqual(
            _BASELINE["total_lines"],
            _COLLECTION.total_lines,
            "the benign corpus has "
            f"{_COLLECTION.total_lines} lines but baseline.json records "
            f"{_BASELINE['total_lines']}; the corpus was edited without a "
            f"baseline refresh -- {REFRESH_HINT}",
        )


if __name__ == "__main__":
    unittest.main()
