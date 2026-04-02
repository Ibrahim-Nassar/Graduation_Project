from __future__ import annotations

import json
from pathlib import Path

from src.evaluation import evaluate_classifier, evaluate_hybrid_pipeline
from src.model import train_attack_classifier


def _write_eval_dataset(path: Path) -> None:
    rows = [
        {
            "text": "timestamp=2026-02-26T10:00:00Z host=wkstn-22 user=analyst01 src_ip=10.10.5.9 process=powershell.exe cmdline=\"powershell -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQ==\" destination=cdn-update.microsoftsupport.example",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "source": "fixture-powershell",
            "label_origin": "analyst_correction",
            "rationale": "Encoded PowerShell command.",
            "confidence": 0.9,
        },
        {
            "text": "Unusual host behavior with script engine anomalies detected",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "source": "fixture-ml-fallback",
            "label_origin": "analyst_correction",
            "rationale": "Analyst labeled as scripting interpreter.",
            "confidence": 0.82,
        },
        {
            "text": "multiple failed login attempts from one source host",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "source": "fixture-bruteforce",
            "label_origin": "analyst_correction",
            "rationale": "Repeated failed authentication.",
            "confidence": 0.88,
        },
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def test_evaluate_classifier_returns_expected_metrics(tmp_path: Path) -> None:
    dataset_path = tmp_path / "eval_dataset.jsonl"
    _write_eval_dataset(dataset_path)

    metrics = evaluate_classifier(dataset_path)

    assert set(metrics.keys()) == {"accuracy", "total_samples", "per_technique_counts", "predicted_vs_actual"}
    assert metrics["total_samples"] == 3
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert metrics["per_technique_counts"] == {"T1059": 2, "T1110": 1}
    assert len(metrics["predicted_vs_actual"]) == 3
    for row in metrics["predicted_vs_actual"]:
        assert set(row.keys()) == {"text", "actual_technique_id", "predicted_technique_id", "is_correct"}

    # Deterministic metrics for same dataset.
    metrics_again = evaluate_classifier(dataset_path)
    assert metrics == metrics_again


def test_evaluate_hybrid_pipeline_returns_mapping_source_stats(tmp_path: Path) -> None:
    dataset_path = tmp_path / "eval_dataset.jsonl"
    _write_eval_dataset(dataset_path)
    model = train_attack_classifier(dataset_path)

    metrics = evaluate_hybrid_pipeline(dataset_path, model=model)

    assert set(metrics.keys()) == {
        "accuracy",
        "total_samples",
        "mapping_source_counts",
        "per_technique_counts",
    }
    assert metrics["total_samples"] == 3
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert metrics["per_technique_counts"] == {"T1059": 2, "T1110": 1}
    assert metrics["mapping_source_counts"].get("rule", 0) >= 1
    assert metrics["mapping_source_counts"].get("ml_fallback", 0) >= 1
    assert sum(metrics["mapping_source_counts"].values()) == 3

    # Deterministic metrics for same dataset/model.
    metrics_again = evaluate_hybrid_pipeline(dataset_path, model=model)
    assert metrics == metrics_again
