from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

from src.contracts import AttackMapping, Result
from src.model import train_attack_classifier
import src.pipeline as pipeline_module
from src.pipeline import run


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _load_raw_log(filename: str) -> str:
    data = json.loads((FIXTURES_DIR / filename).read_text(encoding="utf-8"))
    return data["raw_log"]


def _write_training_dataset(path: Path) -> None:
    rows = [
        {
            "text": "powershell encoded command execution",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "source": "seed-a",
            "label_origin": "analyst_correction",
            "rationale": "Encoded PowerShell execution.",
            "confidence": 0.9,
        },
        {
            "text": "multiple authentication failures from one source",
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


@pytest.mark.parametrize(
    ("fixture_name", "expected_technique"),
    [
        ("powershell_abuse_1.json", "T1059"),
        ("dns_tunnel_1.json", "T1071"),
        ("credential_misuse_1.json", "T1110"),
    ],
)
def test_pipeline_on_fixtures(fixture_name: str, expected_technique: str) -> None:
    raw_log = _load_raw_log(fixture_name)
    result = run(raw_log)

    # Re-validate through contract to assert strict schema compatibility.
    validated = Result.model_validate(result.model_dump())

    assert len(validated.entities) >= 2
    assert len(validated.attack_mapping) >= 1
    assert any(m.technique_id == expected_technique for m in validated.attack_mapping)

    for mapping in validated.attack_mapping:
        assert 0.0 <= mapping.confidence <= 1.0
        assert mapping.evidence_refs
        for evidence_ref in mapping.evidence_refs:
            assert evidence_ref in raw_log

    for entity in validated.entities:
        if entity.start is not None and entity.end is not None:
            assert raw_log[entity.start : entity.end] == entity.value
        else:
            assert entity.value in raw_log

    assert len(validated.epc.checklist) >= 2


@pytest.mark.parametrize(
    ("fixture_name", "expected_normalized_fields"),
    [
        (
            "powershell_abuse_1.json",
            {
                "timestamp": "2026-02-26T10:00:00Z",
                "username": "analyst01",
                "hostname": "wkstn-22",
                "process": "powershell.exe",
                "command_line": "powershell -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQ==",
                "source_ip": "10.10.5.9",
                "domain": "cdn-update.microsoftsupport.example",
            },
        ),
        (
            "dns_tunnel_1.json",
            {
                "timestamp": "2026-02-26T10:11:00Z",
                "username": "svc_backup",
                "source_ip": "10.0.0.15",
                "domain": "aj39dk2m9b.data-transfer.example.com",
            },
        ),
        (
            "credential_misuse_1.json",
            {
                "timestamp": "2026-02-26T11:00:00Z",
                "username": "admin",
                "source_ip": "172.16.1.20",
                "domain": "server-admin.corp.local",
            },
        ),
    ],
)
def test_pipeline_normalizes_structured_fields(
    fixture_name: str, expected_normalized_fields: dict[str, str]
) -> None:
    raw_log = _load_raw_log(fixture_name)
    result = run(raw_log)
    normalized = result.audit["normalized_event"]

    assert isinstance(normalized, dict)
    assert "raw_length" not in normalized

    for field, expected_value in expected_normalized_fields.items():
        assert normalized.get(field) == expected_value

    allowed_keys = {
        "timestamp",
        "username",
        "hostname",
        "process",
        "command_line",
        "source_ip",
        "destination_ip",
        "domain",
    }
    assert set(normalized.keys()).issubset(allowed_keys)


@pytest.mark.parametrize(
    "fixture_name",
    ["powershell_abuse_1.json", "dns_tunnel_1.json", "credential_misuse_1.json"],
)
def test_pipeline_deterministic_outputs(fixture_name: str) -> None:
    raw_log = _load_raw_log(fixture_name)
    result1 = run(raw_log)
    result2 = run(raw_log)
    assert result1.model_dump() == result2.model_dump()


def test_pipeline_without_matching_rule_fails_validation() -> None:
    raw_log = "System health check complete. User session normal."
    with pytest.raises(ValidationError):
        run(raw_log)


def test_pipeline_without_matching_rule_and_no_model_still_fails_validation() -> None:
    raw_log = "Scheduled backup completed successfully with no alerts."
    with pytest.raises(ValidationError):
        run(raw_log, model=None)


def test_pipeline_ml_fallback_for_non_matching_log(tmp_path: Path) -> None:
    dataset_path = tmp_path / "training.jsonl"
    _write_training_dataset(dataset_path)
    model = train_attack_classifier(dataset_path)

    raw_log = "Unexpected script behavior observed on host endpoint."
    result = run(raw_log, model=model)

    validated = Result.model_validate(result.model_dump())
    assert len(validated.attack_mapping) == 1
    mapping = validated.attack_mapping[0]
    assert mapping.technique_id in {"T1059", "T1110"}
    assert 0.0 <= mapping.confidence <= 1.0
    assert mapping.evidence_refs == ["ml_prediction"]
    assert "ML fallback prediction" in mapping.rationale
    assert "model-predicted fallback" in validated.epc.explain
    assert result.audit["mapping_source"] == "ml_fallback"

    # Deterministic predictions for identical input/model.
    result_again = run(raw_log, model=model)
    assert result.model_dump() == result_again.model_dump()


def test_pipeline_rule_mappings_take_priority_over_ml(tmp_path: Path) -> None:
    dataset_path = tmp_path / "training.jsonl"
    _write_training_dataset(dataset_path)
    model = train_attack_classifier(dataset_path)

    raw_log = _load_raw_log("powershell_abuse_1.json")
    result = run(raw_log, model=model)

    assert any(mapping.technique_id == "T1059" for mapping in result.attack_mapping)
    assert result.audit["mapping_source"] == "rule"
    assert all(mapping.evidence_refs != ["ml_prediction"] for mapping in result.attack_mapping)


def test_invalid_confidence_fails_validation() -> None:
    with pytest.raises(ValidationError):
        AttackMapping(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            confidence=1.2,
            rationale="Invalid confidence for negative test.",
            evidence_refs=["powershell", "-enc"],
        )


def test_pipeline_enrichment_adds_results_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_log = _load_raw_log("powershell_abuse_1.json")

    class _FakeIocModule:
        @staticmethod
        def scan_ioc(value: str, providers: dict[str, bool] | None = None, api_keys: dict[str, str] | None = None) -> dict:
            return {
                "ioc": value,
                "type": "ip" if value.count(".") == 3 else "domain",
                "status": "unknown",
                "score": 0,
                "providers": {"stub": {"provider": "stub", "ioc": value, "type": "ip", "status": "unknown", "score": 0, "details": {}}},
            }

    monkeypatch.setattr(pipeline_module, "_IOC_MODULE_CACHE", None)
    monkeypatch.setattr(pipeline_module, "_load_ioc_enrichment_module", lambda: _FakeIocModule)
    result = run(raw_log, enrich_iocs=True)

    enrichment = result.audit.get("ioc_enrichment")
    assert isinstance(enrichment, list)
    assert len(enrichment) >= 1
    assert any(item.get("ioc") == "10.10.5.9" for item in enrichment)


def test_pipeline_without_enrichable_iocs_keeps_core_behavior_with_enrichment_enabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dataset_path = tmp_path / "training.jsonl"
    _write_training_dataset(dataset_path)
    model = train_attack_classifier(dataset_path)

    calls: list[str] = []

    class _FakeIocModule:
        @staticmethod
        def scan_ioc(value: str, providers: dict[str, bool] | None = None, api_keys: dict[str, str] | None = None) -> dict:
            calls.append(value)
            return {"ioc": value}

    monkeypatch.setattr(pipeline_module, "_IOC_MODULE_CACHE", None)
    monkeypatch.setattr(pipeline_module, "_load_ioc_enrichment_module", lambda: _FakeIocModule)
    result = run("host health check complete", model=model, enrich_iocs=True)

    assert result.attack_mapping
    assert result.audit["mapping_source"] == "ml_fallback"
    assert result.audit.get("ioc_enrichment") == []
    assert calls == []


def test_pipeline_enrichment_deduplicates_iocs(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_log = (
        "timestamp=2026-02-26T10:00:00Z src_ip=8.8.8.8 dst_ip=8.8.8.8 "
        "qname=example.com target=example.com process=powershell.exe cmdline=\"powershell -enc AAA=\""
    )
    calls: list[str] = []

    class _FakeIocModule:
        @staticmethod
        def scan_ioc(value: str, providers: dict[str, bool] | None = None, api_keys: dict[str, str] | None = None) -> dict:
            calls.append(value)
            return {"ioc": value, "status": "unknown", "score": 0, "providers": {}}

    monkeypatch.setattr(pipeline_module, "_IOC_MODULE_CACHE", None)
    monkeypatch.setattr(pipeline_module, "_load_ioc_enrichment_module", lambda: _FakeIocModule)
    result = run(raw_log, enrich_iocs=True)

    assert result.attack_mapping
    assert calls.count("8.8.8.8") == 1
    assert calls.count("example.com") == 1


def test_pipeline_enrichment_failure_does_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_log = _load_raw_log("powershell_abuse_1.json")

    class _FakeIocModule:
        @staticmethod
        def scan_ioc(value: str, providers: dict[str, bool] | None = None, api_keys: dict[str, str] | None = None) -> dict:
            raise RuntimeError("boom")

    monkeypatch.setattr(pipeline_module, "_IOC_MODULE_CACHE", None)
    monkeypatch.setattr(pipeline_module, "_load_ioc_enrichment_module", lambda: _FakeIocModule)
    result = run(raw_log, enrich_iocs=True)

    enrichment = result.audit.get("ioc_enrichment")
    assert isinstance(enrichment, list)
    assert enrichment
    assert all(item.get("status") == "error" for item in enrichment)


def test_ioc_loader_returns_module_when_direct_import_available(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = object()

    def fake_import(name: str):
        assert name == "ioc_enrichment"
        return sentinel

    monkeypatch.setattr(pipeline_module, "_IOC_MODULE_CACHE", None)
    monkeypatch.setattr(pipeline_module.importlib, "import_module", fake_import)
    module = pipeline_module._load_ioc_enrichment_module()

    assert module is sentinel
    assert pipeline_module._IOC_MODULE_CACHE is sentinel


def test_ioc_loader_returns_none_when_import_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_import(name: str):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(pipeline_module, "_IOC_MODULE_CACHE", None)
    monkeypatch.setattr(pipeline_module.importlib, "import_module", fake_import)
    monkeypatch.setattr(pipeline_module, "_ioc_enrichment_search_paths", lambda: [])

    module = pipeline_module._load_ioc_enrichment_module()
    assert module is None


def test_ioc_loader_uses_fallback_search_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ioc_src = tmp_path / "ioc_src"
    ioc_src.mkdir(parents=True, exist_ok=True)
    sentinel = object()
    state = {"calls": 0}

    def staged_import(name: str):
        assert name == "ioc_enrichment"
        state["calls"] += 1
        if state["calls"] == 1:
            raise ModuleNotFoundError(name)
        assert str(ioc_src) in sys.path
        return sentinel

    monkeypatch.setattr(pipeline_module, "_IOC_MODULE_CACHE", None)
    monkeypatch.setattr(pipeline_module, "_ioc_enrichment_search_paths", lambda: [ioc_src])
    monkeypatch.setattr(pipeline_module.importlib, "import_module", staged_import)

    module = pipeline_module._load_ioc_enrichment_module()
    assert module is sentinel
