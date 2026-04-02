from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from src.dataset import ExportedTrainingRow
from src.model import predict_attack, train_attack_classifier
from src.pipeline import run


def _load_dataset_rows(dataset_path: Path | str) -> list[ExportedTrainingRow]:
    path = Path(dataset_path)
    rows: list[ExportedTrainingRow] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        rows.append(ExportedTrainingRow.model_validate(payload))
    return rows


def evaluate_classifier(dataset_path: Path | str) -> dict[str, Any]:
    rows = _load_dataset_rows(dataset_path)
    model = train_attack_classifier(dataset_path)

    predicted_vs_actual: list[dict[str, str | bool]] = []
    technique_counts = Counter(row.technique_id for row in rows)
    correct = 0

    for row in rows:
        prediction = predict_attack(row.text, model)
        predicted_id = str(prediction["technique_id"])
        is_correct = predicted_id == row.technique_id
        if is_correct:
            correct += 1
        predicted_vs_actual.append(
            {
                "text": row.text,
                "actual_technique_id": row.technique_id,
                "predicted_technique_id": predicted_id,
                "is_correct": is_correct,
            }
        )

    total_samples = len(rows)
    accuracy = (correct / total_samples) if total_samples else 0.0

    return {
        "accuracy": accuracy,
        "total_samples": total_samples,
        "per_technique_counts": dict(sorted(technique_counts.items())),
        "predicted_vs_actual": predicted_vs_actual,
    }


def evaluate_hybrid_pipeline(dataset_path: Path | str, model: Any) -> dict[str, Any]:
    rows = _load_dataset_rows(dataset_path)
    technique_counts = Counter(row.technique_id for row in rows)
    mapping_source_counts: Counter[str] = Counter()
    correct = 0

    for row in rows:
        result = run(row.text, model=model)
        mapping_source = str(result.audit.get("mapping_source", "unknown"))
        mapping_source_counts[mapping_source] += 1

        predicted_id = result.attack_mapping[0].technique_id
        if predicted_id == row.technique_id:
            correct += 1

    total_samples = len(rows)
    accuracy = (correct / total_samples) if total_samples else 0.0

    return {
        "accuracy": accuracy,
        "total_samples": total_samples,
        "mapping_source_counts": dict(sorted(mapping_source_counts.items())),
        "per_technique_counts": dict(sorted(technique_counts.items())),
    }
