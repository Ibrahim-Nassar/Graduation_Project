from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.feedback import CORRECTIONS_FILE, save_correction
from src.pipeline import run


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _load_raw_log(filename: str) -> str:
    data = json.loads((FIXTURES_DIR / filename).read_text(encoding="utf-8"))
    return data["raw_log"]


def _valid_corrected_mapping() -> list[dict]:
    return [
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "confidence": 0.91,
            "rationale": "Analyst confirmed encoded PowerShell command execution.",
            "evidence_refs": ["powershell", "-enc"],
        }
    ]


def test_save_correction_writes_valid_json_line(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import src.feedback as feedback_module

    raw_log = _load_raw_log("powershell_abuse_1.json")
    result = run(raw_log)
    result.audit["raw_event"] = raw_log

    data_dir = tmp_path / "data"
    monkeypatch.setattr(feedback_module, "DATA_DIR", data_dir)

    saved = save_correction(
        result,
        corrected_attack_mapping=_valid_corrected_mapping(),
        analyst_note="Confirmed by SOC Tier 2.",
        source_fixture="powershell_abuse_1.json",
    )

    output_path = data_dir / CORRECTIONS_FILE
    assert output_path.exists()

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    parsed = json.loads(lines[0])
    assert parsed == saved
    assert parsed["raw_event"] == raw_log
    assert isinstance(parsed["original_attack_mapping"], list) and parsed["original_attack_mapping"]
    assert isinstance(parsed["corrected_attack_mapping"], list) and parsed["corrected_attack_mapping"]
    assert parsed["corrected_attack_mapping"][0]["technique_id"] == "T1059"


def test_save_correction_rejects_invalid_corrected_mapping(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import src.feedback as feedback_module

    raw_log = _load_raw_log("powershell_abuse_1.json")
    result = run(raw_log)
    result.audit["raw_event"] = raw_log

    data_dir = tmp_path / "data"
    monkeypatch.setattr(feedback_module, "DATA_DIR", data_dir)

    invalid_mapping = [
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "confidence": 3.0,
            "rationale": "Invalid confidence.",
            "evidence_refs": ["powershell", "-enc"],
        }
    ]

    with pytest.raises(ValidationError):
        save_correction(result, corrected_attack_mapping=invalid_mapping)

    assert not (data_dir / CORRECTIONS_FILE).exists()


def test_save_correction_appends_two_lines(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import src.feedback as feedback_module

    raw_log = _load_raw_log("powershell_abuse_1.json")
    result = run(raw_log)
    result.audit["raw_event"] = raw_log

    data_dir = tmp_path / "data"
    monkeypatch.setattr(feedback_module, "DATA_DIR", data_dir)

    save_correction(result, corrected_attack_mapping=_valid_corrected_mapping(), source_fixture="fixture-a")
    save_correction(result, corrected_attack_mapping=_valid_corrected_mapping(), source_fixture="fixture-b")

    output_path = data_dir / CORRECTIONS_FILE
    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["source_fixture"] == "fixture-a"
    assert json.loads(lines[1])["source_fixture"] == "fixture-b"
