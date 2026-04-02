from __future__ import annotations

import json
from pathlib import Path

from src.model import load_model, predict_attack, save_model, train_attack_classifier


def _write_dataset(path: Path) -> None:
    rows = [
        {
            "text": "powershell -enc payload execution from workstation",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "source": "fixture-a",
            "label_origin": "analyst_correction",
            "rationale": "Encoded PowerShell command observed.",
            "confidence": 0.9,
        },
        {
            "text": "repeated failed login attempts from single source ip",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "source": "fixture-b",
            "label_origin": "analyst_correction",
            "rationale": "Multiple failed authentications.",
            "confidence": 0.88,
        },
        {
            "text": "dns queries to randomized subdomains indicate tunnel",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "source": "fixture-c",
            "label_origin": "analyst_correction",
            "rationale": "High-volume DNS with random labels.",
            "confidence": 0.85,
        },
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def test_train_attack_classifier_runs_successfully(tmp_path: Path) -> None:
    dataset_path = tmp_path / "dataset.jsonl"
    _write_dataset(dataset_path)

    model = train_attack_classifier(dataset_path)
    assert model is not None
    assert hasattr(model, "predict")
    assert hasattr(model, "predict_proba")


def test_predict_attack_returns_valid_label_and_confidence(tmp_path: Path) -> None:
    dataset_path = tmp_path / "dataset.jsonl"
    _write_dataset(dataset_path)
    model = train_attack_classifier(dataset_path)

    prediction = predict_attack("powershell encoded command execution", model)
    assert prediction["technique_id"] in {"T1059", "T1110", "T1071"}
    assert 0.0 <= prediction["confidence"] <= 1.0


def test_predict_attack_is_deterministic_for_same_input(tmp_path: Path) -> None:
    dataset_path = tmp_path / "dataset.jsonl"
    _write_dataset(dataset_path)
    model = train_attack_classifier(dataset_path)

    text = "multiple failed login attempts from one host"
    first = predict_attack(text, model)
    second = predict_attack(text, model)
    assert first == second


def test_model_can_be_saved_and_loaded_with_same_predictions(tmp_path: Path) -> None:
    dataset_path = tmp_path / "dataset.jsonl"
    model_path = tmp_path / "models" / "attack-model.pkl"
    _write_dataset(dataset_path)

    trained_model = train_attack_classifier(dataset_path)
    save_model(trained_model, model_path)
    assert model_path.exists()

    loaded_model = load_model(model_path)
    text = "powershell encoded command execution"
    before = predict_attack(text, trained_model)
    after = predict_attack(text, loaded_model)
    assert before == after
