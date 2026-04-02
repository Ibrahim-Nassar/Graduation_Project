from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.dataset import export_training_dataset
from src.feedback import CORRECTIONS_FILE, save_correction
from src.pipeline import run


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _load_raw_log(filename: str) -> str:
    data = json.loads((FIXTURES_DIR / filename).read_text(encoding="utf-8"))
    return data["raw_log"]


def _corrected_mapping(
    technique_id: str = "T1059",
    technique_name: str = "Command and Scripting Interpreter",
    confidence: float = 0.91,
) -> list[dict]:
    return [
        {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "confidence": confidence,
            "rationale": "Analyst confirmed behavior.",
            "evidence_refs": ["evidence-token"],
        }
    ]


def test_export_training_dataset_single_row(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import src.feedback as feedback_module

    raw_log = _load_raw_log("powershell_abuse_1.json")
    result = run(raw_log)
    result.audit["raw_event"] = raw_log

    corrections_dir = tmp_path / "data"
    corrections_path = corrections_dir / CORRECTIONS_FILE
    output_path = tmp_path / "exports" / "training.jsonl"
    monkeypatch.setattr(feedback_module, "DATA_DIR", corrections_dir)

    save_correction(
        result=result,
        corrected_attack_mapping=_corrected_mapping(),
        analyst_note="validated label",
        source_fixture="powershell_abuse_1.json",
    )

    exported = export_training_dataset(corrections_path, output_path)
    assert len(exported) == 1
    row = exported[0]
    assert row["text"] == raw_log
    assert row["technique_id"] == "T1059"
    assert row["source"] == "powershell_abuse_1.json"
    assert row["label_origin"] == "analyst_correction"


def test_export_training_dataset_multiple_records(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import src.feedback as feedback_module

    raw_log_a = _load_raw_log("powershell_abuse_1.json")
    result_a = run(raw_log_a)
    result_a.audit["raw_event"] = raw_log_a

    raw_log_b = _load_raw_log("credential_misuse_1.json")
    result_b = run(raw_log_b)
    result_b.audit["raw_event"] = raw_log_b

    corrections_dir = tmp_path / "data"
    corrections_path = corrections_dir / CORRECTIONS_FILE
    output_path = tmp_path / "exports" / "training.jsonl"
    monkeypatch.setattr(feedback_module, "DATA_DIR", corrections_dir)

    save_correction(result_a, corrected_attack_mapping=_corrected_mapping(), source_fixture="fixture-a")
    save_correction(
        result_b,
        corrected_attack_mapping=_corrected_mapping(
            technique_id="T1110",
            technique_name="Brute Force",
            confidence=0.88,
        ),
        source_fixture="fixture-b",
    )

    exported = export_training_dataset(corrections_path, output_path)
    assert len(exported) == 2
    assert exported[0]["source"] == "fixture-a"
    assert exported[1]["source"] == "fixture-b"
    assert exported[0]["technique_id"] == "T1059"
    assert exported[1]["technique_id"] == "T1110"


def test_export_training_dataset_invalid_input_fails_validation(tmp_path: Path) -> None:
    corrections_path = tmp_path / "data" / CORRECTIONS_FILE
    output_path = tmp_path / "exports" / "training.jsonl"
    corrections_path.parent.mkdir(parents=True, exist_ok=True)

    invalid_record = {
        "raw_event": "event text",
        "normalized_event": {"username": "alice"},
        "entities": [],
        "original_attack_mapping": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "confidence": 0.9,
                "rationale": "Original mapping",
                "evidence_refs": ["token"],
            }
        ],
        "corrected_attack_mapping": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "confidence": 9.9,
                "rationale": "Invalid confidence",
                "evidence_refs": ["token"],
            }
        ],
        "analyst_note": None,
        "created_at": "2026-03-06T12:00:00Z",
        "source_fixture": "broken.json",
    }
    corrections_path.write_text(json.dumps(invalid_record) + "\n", encoding="utf-8")

    with pytest.raises(ValidationError):
        export_training_dataset(corrections_path, output_path)


def test_export_training_dataset_jsonl_is_valid_and_deterministic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import src.feedback as feedback_module

    raw_log = _load_raw_log("powershell_abuse_1.json")
    result = run(raw_log)
    result.audit["raw_event"] = raw_log

    corrections_dir = tmp_path / "data"
    corrections_path = corrections_dir / CORRECTIONS_FILE
    output_path = tmp_path / "exports" / "training.jsonl"
    monkeypatch.setattr(feedback_module, "DATA_DIR", corrections_dir)

    save_correction(
        result=result,
        corrected_attack_mapping=_corrected_mapping(),
        source_fixture="deterministic-fixture",
    )

    first_export = export_training_dataset(corrections_path, output_path)
    first_lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    parsed_first = [json.loads(line) for line in first_lines]
    assert parsed_first == first_export

    second_export = export_training_dataset(corrections_path, output_path)
    second_lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert first_export == second_export
    assert first_lines == second_lines
