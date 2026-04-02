from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import src.cli as cli_module
from src.model import save_model, train_attack_classifier


def _write_training_dataset(path: Path) -> None:
    rows = [
        {
            "text": "powershell encoded command execution",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "source": "seed-a",
            "label_origin": "analyst_correction",
            "rationale": "Encoded PowerShell activity.",
            "confidence": 0.9,
        },
        {
            "text": "multiple authentication failures from one source host",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "source": "seed-b",
            "label_origin": "analyst_correction",
            "rationale": "Repeated failed logins.",
            "confidence": 0.88,
        },
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def test_cli_runs_successfully_without_model() -> None:
    raw_log = (
        "timestamp=2026-02-26T10:00:00Z host=wkstn-22 user=analyst01 src_ip=10.10.5.9 "
        "process=powershell.exe cmdline=\"powershell -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQ==\" "
        "destination=cdn-update.microsoftsupport.example"
    )
    completed = subprocess.run(
        [sys.executable, "-m", "src.cli", raw_log],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0

    payload = json.loads(completed.stdout)
    assert "result" in payload
    result = payload["result"]
    assert set(result.keys()) == {"technique_id", "confidence", "mapping_source", "explain", "checklist"}
    assert result["mapping_source"] == "rule"
    assert 0.0 <= result["confidence"] <= 1.0


def test_cli_runs_successfully_with_model(tmp_path: Path) -> None:
    tmp_dir = tmp_path / "cli-model-artifacts"
    dataset_path = tmp_dir / "training.jsonl"
    model_path = tmp_dir / "model.pkl"
    _write_training_dataset(dataset_path)

    model = train_attack_classifier(dataset_path)
    save_model(model, model_path)

    raw_log = "Unusual script-like host behavior observed with suspicious process activity."
    completed = subprocess.run(
        [sys.executable, "-m", "src.cli", "--model", str(model_path), raw_log],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0

    payload = json.loads(completed.stdout)
    assert "result" in payload
    result = payload["result"]
    assert set(result.keys()) == {"technique_id", "confidence", "mapping_source", "explain", "checklist"}
    assert result["mapping_source"] == "ml_fallback"
    assert 0.0 <= result["confidence"] <= 1.0


def test_cli_training_command_creates_model_file(tmp_path: Path) -> None:
    dataset_path = tmp_path / "train" / "dataset.jsonl"
    model_path = tmp_path / "models" / "trained.pkl"
    _write_training_dataset(dataset_path)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.cli",
            "--train",
            str(dataset_path),
            "--output-model",
            str(model_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert model_path.exists()

    payload = json.loads(completed.stdout)
    assert "training" in payload
    assert payload["training"]["status"] == "ok"
    assert payload["training"]["dataset_path"] == str(dataset_path)
    assert payload["training"]["model_path"] == str(model_path)


def test_cli_inference_with_enrichment_flag_passes_pipeline_option(monkeypatch, capsys) -> None:
    calls: list[dict[str, object]] = []

    def fake_run(raw_log: str, model=None, **kwargs):
        calls.append({"raw_log": raw_log, "model": model, "kwargs": kwargs})
        return SimpleNamespace(
            attack_mapping=[
                SimpleNamespace(technique_id="T1059", confidence=0.9),
            ],
            epc=SimpleNamespace(explain="explain", checklist=["a", "b"]),
            audit={"mapping_source": "rule", "ioc_enrichment": [{"ioc": "8.8.8.8", "status": "unknown"}]},
        )

    monkeypatch.setattr(cli_module, "run", fake_run)
    exit_code = cli_module.main(["--enrich-iocs", "src_ip=8.8.8.8 process=powershell.exe cmdline=\"powershell -enc A\""])

    assert exit_code == 0
    assert len(calls) == 1
    assert calls[0]["kwargs"] == {"enrich_iocs": True}

    payload = json.loads(capsys.readouterr().out)
    assert payload["result"]["ioc_enrichment"] == [{"ioc": "8.8.8.8", "status": "unknown"}]


def test_cli_inference_default_path_omits_enrichment_output(monkeypatch, capsys) -> None:
    def fake_run(raw_log: str, model=None, **kwargs):
        return SimpleNamespace(
            attack_mapping=[SimpleNamespace(technique_id="T1059", confidence=0.9)],
            epc=SimpleNamespace(explain="explain", checklist=["a", "b"]),
            audit={"mapping_source": "rule", "ioc_enrichment": [{"ioc": "8.8.8.8"}]},
        )

    monkeypatch.setattr(cli_module, "run", fake_run)
    exit_code = cli_module.main(["src_ip=8.8.8.8 process=powershell.exe cmdline=\"powershell -enc A\""])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert "ioc_enrichment" not in payload["result"]


def test_cli_unmatched_log_returns_structured_error() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "src.cli", "System health check complete. User session normal."],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 2
    assert completed.stdout == ""

    payload = json.loads(completed.stderr)
    assert payload["error"]["type"] == "validation_error"
    assert "No ATT&CK mapping could be produced" in payload["error"]["message"]
    assert isinstance(payload["error"]["details"], list)
    assert payload["error"]["details"]
