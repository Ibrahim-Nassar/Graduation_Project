"""Benign-corpus false-positive report.

Runs the deterministic pipeline over every ``*.log`` file under
``tests/data/benign/`` (recursively, one line at a time) and reports which
lines produce an ATT&CK mapping.  Every mapping on this corpus is by
definition a false positive: the corpus only contains traffic a healthy
host or device produces during routine operation.

This module is also the loader used by ``tests/test_benign_corpus.py`` --
the regression gate imports :func:`collect` from here so the test and the
report can never drift apart.

Usage (from the repository root)::

    python scripts/benign_report.py
    python scripts/benign_report.py --json /tmp/benign.json
    python scripts/benign_report.py --update-baseline
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.pipeline import run  # noqa: E402  (needs REPO_ROOT on sys.path first)

BENIGN_DIR = REPO_ROOT / "tests" / "data" / "benign"
BASELINE_PATH = BENIGN_DIR / "baseline.json"

STRENGTH_ORDER = ("strong", "moderate", "weak")


class Finding(NamedTuple):
    """One technique mapped onto one benign log line."""

    file: str
    line: int
    technique_id: str
    evidence_strength: str
    rationale: str
    raw: str

    def key(self) -> tuple[str, int, str]:
        return (self.file, self.line, self.technique_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "technique_id": self.technique_id,
            "evidence_strength": self.evidence_strength,
            "rationale": self.rationale,
        }


class PipelineError(NamedTuple):
    """A benign log line the pipeline could not process at all."""

    file: str
    line: int
    raw: str
    traceback_text: str


class Collection(NamedTuple):
    total_lines: int
    findings: list[Finding]
    errors: list[PipelineError]

    @property
    def mapped_lines(self) -> int:
        return len({(finding.file, finding.line) for finding in self.findings})

    @property
    def counts_by_strength(self) -> dict[str, int]:
        counter = Counter(finding.evidence_strength for finding in self.findings)
        counts = {strength: counter.get(strength, 0) for strength in STRENGTH_ORDER}
        for strength, count in counter.items():
            counts.setdefault(strength, count)
        return counts

    @property
    def counts_by_technique(self) -> list[tuple[str, int]]:
        counter = Counter(finding.technique_id for finding in self.findings)
        return sorted(counter.items(), key=lambda item: (-item[1], item[0]))


def log_files(benign_dir: Path = BENIGN_DIR) -> list[Path]:
    """Every ``*.log`` under the benign corpus, recursively, in stable order."""
    return sorted(benign_dir.rglob("*.log"))


def iter_lines(benign_dir: Path = BENIGN_DIR) -> Iterator[tuple[str, int, str]]:
    """Yield ``(relative_path, 1-based line number, raw line)`` for non-empty lines."""
    for path in log_files(benign_dir):
        relative = path.relative_to(benign_dir).as_posix()
        text = path.read_text(encoding="utf-8")
        for index, raw_line in enumerate(text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            yield relative, index, stripped


def collect(benign_dir: Path = BENIGN_DIR) -> Collection:
    """Run the pipeline over the corpus and collect mappings and errors."""
    total_lines = 0
    findings: list[Finding] = []
    errors: list[PipelineError] = []

    for relative, line_number, raw_line in iter_lines(benign_dir):
        total_lines += 1
        try:
            result = run(raw_line, model=None)
        except Exception:  # noqa: BLE001 -- the report exists to surface these
            errors.append(
                PipelineError(
                    file=relative,
                    line=line_number,
                    raw=raw_line,
                    traceback_text=traceback.format_exc(),
                )
            )
            continue
        for mapping in result.attack_mapping:
            findings.append(
                Finding(
                    file=relative,
                    line=line_number,
                    technique_id=mapping.technique_id,
                    evidence_strength=mapping.evidence_strength,
                    rationale=mapping.rationale,
                    raw=raw_line,
                )
            )

    findings.sort(key=lambda finding: finding.key())
    return Collection(total_lines=total_lines, findings=findings, errors=errors)


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def baseline_payload(collection: Collection) -> dict[str, Any]:
    """The exact JSON document written by ``--update-baseline``."""
    return {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "total_lines": collection.total_lines,
        "counts_by_strength": collection.counts_by_strength,
        "findings": [
            {
                "file": finding.file,
                "line": finding.line,
                "technique_id": finding.technique_id,
            }
            for finding in sorted(collection.findings, key=lambda item: item.key())
        ],
    }


def write_baseline(collection: Collection, path: Path = BASELINE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = baseline_payload(collection)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def print_report(collection: Collection) -> None:
    total = collection.total_lines
    mapped = collection.mapped_lines
    percentage = (mapped / total * 100.0) if total else 0.0

    print("=" * 78)
    print("Benign corpus false-positive report")
    print("=" * 78)
    print(f"corpus directory : {BENIGN_DIR.relative_to(REPO_ROOT).as_posix()}")
    print(f"log files        : {len(log_files())}")
    print(f"total lines      : {total}")
    print(f"mapped lines     : {mapped}")
    print(f"mapped/total     : {percentage:.2f}%")
    print(f"total findings   : {len(collection.findings)}")
    print(f"errors           : {len(collection.errors)}")

    print()
    print("-- counts by evidence_strength " + "-" * 46)
    counts_by_strength = collection.counts_by_strength
    if not any(counts_by_strength.values()):
        print("  (none)")
    else:
        for strength, count in counts_by_strength.items():
            print(f"  {strength:10s} {count}")

    print()
    print("-- counts by technique_id (descending) " + "-" * 38)
    counts_by_technique = collection.counts_by_technique
    if not counts_by_technique:
        print("  (none)")
    else:
        for technique_id, count in counts_by_technique:
            print(f"  {technique_id:12s} {count}")

    print()
    print("-- mapped lines grouped by technique_id " + "-" * 37)
    if not collection.findings:
        print("  (none)")
    else:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for finding in collection.findings:
            grouped[finding.technique_id].append(finding)
        for technique_id, _ in counts_by_technique:
            print(f"  {technique_id} ({len(grouped[technique_id])})")
            for finding in grouped[technique_id]:
                location = f"{finding.file}:{finding.line}"
                print(f"    [{finding.evidence_strength}] {location}")
                print(f"      {finding.raw[:120]}")

    print()
    print("-- errors " + "-" * 67)
    if not collection.errors:
        print("  (none)")
    else:
        for error in collection.errors:
            print(f"  {error.file}:{error.line}")
            print(f"    {error.raw[:120]}")
            for tb_line in error.traceback_text.rstrip().splitlines():
                print(f"    | {tb_line}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report the pipeline's false positives on the benign log corpus.",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        metavar="PATH",
        help="also write the collected findings as JSON to PATH",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help=f"rewrite {BASELINE_PATH.relative_to(REPO_ROOT).as_posix()} from this run",
    )
    args = parser.parse_args(argv)

    collection = collect()
    print_report(collection)

    if args.json_path:
        payload = {
            "total_lines": collection.total_lines,
            "mapped_lines": collection.mapped_lines,
            "counts_by_strength": collection.counts_by_strength,
            "counts_by_technique": dict(collection.counts_by_technique),
            "findings": [finding.to_dict() for finding in collection.findings],
            "errors": [
                {
                    "file": error.file,
                    "line": error.line,
                    "raw": error.raw,
                    "traceback": error.traceback_text,
                }
                for error in collection.errors
            ],
        }
        json_path = Path(args.json_path)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print()
        print(f"wrote findings JSON to {json_path}")

    if args.update_baseline:
        write_baseline(collection)
        print()
        print(f"wrote baseline to {BASELINE_PATH.relative_to(REPO_ROOT).as_posix()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
