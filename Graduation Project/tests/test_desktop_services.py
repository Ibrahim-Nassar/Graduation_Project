from __future__ import annotations

from pathlib import Path

import src.desktop_services as desktop_services


def test_collect_iocs_merges_inputs_and_deduplicates(tmp_path: Path) -> None:
    csv_path = tmp_path / "iocs.csv"
    csv_path.write_text("ioc\n8.8.8.8\nexample.com\n8.8.8.8\n", encoding="utf-8")

    values = desktop_services.collect_iocs(
        single_ioc="example.com",
        bulk_text="1.1.1.1\nexample.com",
        file_path=str(csv_path),
    )
    assert values == ["example.com", "1.1.1.1", "8.8.8.8"]


def test_scan_iocs_manual_type_override_uses_forced_provider_path(monkeypatch) -> None:
    calls: list[str] = []

    class FakeModule:
        IOC_TYPE_IP = "ip"

        @staticmethod
        def detect_ioc_type(value: str) -> str:
            return "domain" if "." in value else "unknown"

        @staticmethod
        def _enabled_providers(providers):
            return providers or {
                "virustotal": True,
                "abuseipdb": True,
                "otx": True,
                "threatfox": True,
            }

        @staticmethod
        def _normalize_provider_result(provider: str, result: dict, ioc: str, ioc_type: str) -> dict:
            normalized = dict(result)
            normalized["provider"] = provider
            normalized["ioc"] = ioc
            normalized["type"] = ioc_type
            normalized.setdefault("details", {})
            normalized.setdefault("score", 0)
            normalized.setdefault("status", "unknown")
            return normalized

        @staticmethod
        def _aggregate_status(provider_results: dict) -> str:
            statuses = [payload.get("status", "unknown") for payload in provider_results.values()]
            if "malicious" in statuses:
                return "malicious"
            if "suspicious" in statuses:
                return "suspicious"
            if "clean" in statuses:
                return "clean"
            return "unknown"

        @staticmethod
        def _aggregate_score(provider_results: dict) -> int:
            scores = [int(payload.get("score", 0)) for payload in provider_results.values()]
            if not scores:
                return 0
            return round(sum(scores) / len(scores))

        @staticmethod
        def vt_lookup(value: str, ioc_type: str, api_key: str | None = None) -> dict:
            return {"status": "unknown", "score": 0, "details": {}}

        @staticmethod
        def abuseipdb_lookup(value: str, api_key: str | None = None) -> dict:
            calls.append(value)
            return {"status": "suspicious", "score": 25, "details": {}}

        @staticmethod
        def otx_lookup(value: str, ioc_type: str, api_key: str | None = None) -> dict:
            return {"status": "unknown", "score": 0, "details": {}}

        @staticmethod
        def threatfox_lookup(value: str, ioc_type: str, api_key: str | None = None) -> dict:
            return {"status": "unknown", "score": 0, "details": {}}

        @staticmethod
        def scan_ioc(value: str, providers=None, api_keys=None) -> dict:
            return {"ioc": value, "type": "domain", "status": "unknown", "score": 0, "providers": {}}

    monkeypatch.setattr(desktop_services, "_load_ioc_module", lambda: FakeModule)
    rows = desktop_services.scan_iocs(
        ["example.com"],
        manual_ioc_type="ip",
        providers={"virustotal": False, "abuseipdb": True, "otx": False, "threatfox": False},
        api_keys={},
    )

    assert len(rows) == 1
    assert rows[0]["detected_type"] == "domain"
    assert rows[0]["effective_type"] == "ip"
    assert calls == ["example.com"]
    assert rows[0]["status"] == "suspicious"


def test_scan_iocs_handles_missing_ioc_module(monkeypatch) -> None:
    monkeypatch.setattr(desktop_services, "_load_ioc_module", lambda: None)
    rows = desktop_services.scan_iocs(
        ["8.8.8.8"],
        manual_ioc_type=None,
        providers={"virustotal": True},
        api_keys={},
    )
    assert rows[0]["status"] == "error"
    assert rows[0]["error_count"] == 1


def test_analyze_soc_log_returns_validation_error_for_non_matching_log() -> None:
    payload = desktop_services.analyze_soc_log("normal health check event with no suspicious behavior")
    assert payload["ok"] is False
    assert "No ATT&CK mapping could be produced" in payload["error"]
