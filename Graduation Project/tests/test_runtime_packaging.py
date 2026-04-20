from __future__ import annotations

import csv
import json
import os
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from src.desktop_services import (
    SessionSettings,
    analyze_soc_log,
    export_json,
    export_soc_csv,
    load_persisted_settings,
    save_persisted_settings,
    scan_iocs,
)
from src.pipeline import _ioc_enrichment_search_paths, run
import src.pipeline as pipeline_module


class _FakeIocModuleForScan:
    IOC_TYPE_IP = "ip"

    def __init__(self) -> None:
        self.vt_called = 0
        self.abuse_called = 0
        self.otx_called = 0
        self.threatfox_called = 0

    def detect_ioc_type(self, ioc: str) -> str:
        return "ip" if ioc.count(".") == 3 else "domain"

    def scan_ioc(
        self,
        ioc: str,
        *,
        providers: dict[str, bool] | None = None,
        api_keys: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        errors = ["scan_error"] if "bad" in ioc else []
        provider_payload = {"status": "clean"}
        if "bad" in ioc:
            provider_payload = {"status": "error", "error": "provider_timeout"}
        return {
            "ioc": ioc,
            "type": self.detect_ioc_type(ioc),
            "status": "clean" if not errors else "unknown",
            "score": 10 if not errors else 0,
            "providers": {
                "virustotal": provider_payload,
            },
            "errors": errors,
        }

    def _enabled_providers(self, providers: dict[str, bool] | None) -> dict[str, bool]:
        defaults = {"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True}
        if providers is not None:
            defaults.update({name: bool(value) for name, value in providers.items()})
        return defaults

    def _normalize_provider_result(
        self,
        provider_name: str,
        payload: dict[str, Any] | None,
        ioc: str,
        ioc_type: str,
    ) -> dict[str, Any]:
        result = dict(payload or {})
        result.setdefault("provider", provider_name)
        result.setdefault("ioc", ioc)
        result.setdefault("type", ioc_type)
        result.setdefault("status", "n/a")
        return result

    def _aggregate_status(self, provider_results: dict[str, dict[str, Any]]) -> str:
        statuses = {str((payload or {}).get("status", "unknown")).lower() for payload in provider_results.values()}
        if "malicious" in statuses:
            return "malicious"
        if "suspicious" in statuses:
            return "suspicious"
        if "clean" in statuses:
            return "clean"
        return "unknown"

    def _aggregate_score(self, provider_results: dict[str, dict[str, Any]]) -> int:
        if not provider_results:
            return 0
        return 10

    def vt_lookup(self, ioc: str, ioc_type: str, api_key: str | None) -> dict[str, Any]:
        self.vt_called += 1
        return {"status": "clean"}

    def abuseipdb_lookup(self, ioc: str, api_key: str | None) -> dict[str, Any]:
        self.abuse_called += 1
        return {"status": "clean"}

    def otx_lookup(self, ioc: str, ioc_type: str, api_key: str | None) -> dict[str, Any]:
        self.otx_called += 1
        return {"status": "clean"}

    def threatfox_lookup(self, ioc: str, ioc_type: str, api_key: str | None) -> dict[str, Any]:
        self.threatfox_called += 1
        return {"status": "clean"}


class _FakeMlModel:
    def __init__(self) -> None:
        self.predict_called = 0
        self.predict_proba_called = 0

    def predict(self, values: list[str]) -> list[str]:
        self.predict_called += 1
        return ["T1059" for _ in values]

    def predict_proba(self, values: list[str]) -> list[Any]:
        self.predict_proba_called += 1
        class _Probabilities(list[float]):
            def argmax(self) -> int:
                return int(max(range(len(self)), key=lambda idx: self[idx]))

        return [_Probabilities([0.1, 0.9]) for _ in values]


class _FakeEnrichmentModule:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def scan_ioc(
        self,
        value: str,
        *,
        providers: dict[str, bool] | None = None,
        api_keys: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self.calls.append(value)
        return {"ioc": value, "status": "clean", "score": 10, "providers": {}, "errors": []}


class IocRemainingEdgeCaseTests(unittest.TestCase):
    def test_provider_disabled_marks_output_na_and_lookup_not_called(self) -> None:
        fake = _FakeIocModuleForScan()
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs(
                ["8.8.8.8"],
                manual_ioc_type="ip",
                providers={"virustotal": False, "abuseipdb": True, "otx": False, "threatfox": False},
                api_keys={},
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["virustotal"], "n/a")
        self.assertEqual(fake.vt_called, 0)

    def test_missing_api_key_behavior_does_not_crash(self) -> None:
        import src.ioc_enrichment as ioc_enrichment

        with patch("src.desktop_services._load_ioc_module", return_value=ioc_enrichment):
            rows = scan_iocs(
                ["8.8.8.8", "evil.example.com"],
                manual_ioc_type=None,
                providers={"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True},
                api_keys={},
            )
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["virustotal"], "n/a")
        self.assertEqual(rows[0]["abuseipdb"], "n/a")
        self.assertEqual(rows[0]["otx"], "n/a")
        self.assertEqual(rows[0]["threatfox"], "n/a")
        self.assertEqual(rows[1]["abuseipdb"], "not_supported")

    def test_multiple_iocs_preserve_order(self) -> None:
        fake = _FakeIocModuleForScan()
        input_iocs = ["first.example.com", "second.example.com", "third.example.com"]
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs(input_iocs, manual_ioc_type=None, providers=None, api_keys=None)
        self.assertEqual([row["ioc"] for row in rows], input_iocs)

    def test_per_ioc_errors_remain_isolated(self) -> None:
        fake = _FakeIocModuleForScan()
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs(["good.example.com", "bad.example.com"], manual_ioc_type=None, providers=None, api_keys=None)
        self.assertEqual(rows[0]["error_count"], 0)
        self.assertGreaterEqual(rows[1]["error_count"], 1)
        self.assertEqual(rows[0]["ioc"], "good.example.com")
        self.assertEqual(rows[1]["ioc"], "bad.example.com")

    def test_empty_ioc_list_returns_empty_result(self) -> None:
        fake = _FakeIocModuleForScan()
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs([], manual_ioc_type=None, providers=None, api_keys=None)
        self.assertEqual(rows, [])


class SocRemainingEdgeCaseTests(unittest.TestCase):
    def test_ml_fallback_calls_model_prediction_path(self) -> None:
        model = _FakeMlModel()
        result = run("routine log line without deterministic matches", model=model)
        dump = result.model_dump(mode="json")
        self.assertEqual(dump["audit"]["mapping_source"], "ml_fallback")
        self.assertEqual(model.predict_called, 1)
        self.assertEqual(model.predict_proba_called, 1)

    def test_enrichment_only_ip_and_domain_and_deduped(self) -> None:
        fake = _FakeEnrichmentModule()
        log = (
            "failed login user=alice src_ip=8.8.8.8 domain=evil.example.com process=powershell "
            "failed login user=alice src_ip=8.8.8.8 domain=evil.example.com "
            "failed login user=alice src_ip=8.8.8.8 domain=evil.example.com"
        )
        with patch("src.pipeline._load_ioc_enrichment_module", return_value=fake):
            result = run(log, enrich_iocs=True)
        dump = result.model_dump(mode="json")
        enrichment_iocs = [item.get("ioc") for item in dump["audit"].get("ioc_enrichment", [])]
        self.assertEqual(enrichment_iocs, ["8.8.8.8", "evil.example.com"])

    def test_no_entity_minimal_entity_edge_is_safe_via_wrapper(self) -> None:
        payload = analyze_soc_log("hello world")
        self.assertFalse(payload["ok"])
        self.assertIn("error", payload)


class SettingsPersistenceTests(unittest.TestCase):
    def test_save_writes_valid_json_and_load_reads_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_settings = Path(tmpdir) / "settings.json"
            settings = SessionSettings(
                api_keys={"virustotal": "vt", "abuseipdb": "", "otx": "o", "threatfox": ""},
                providers={"virustotal": True, "abuseipdb": False, "otx": True, "threatfox": False},
                history_enabled=True,
            )
            with patch("src.desktop_services._SETTINGS_FILE", temp_settings):
                saved = save_persisted_settings(settings)
                loaded = load_persisted_settings()
            self.assertTrue(saved)
            raw = json.loads(temp_settings.read_text(encoding="utf-8"))
            self.assertIn("api_keys", raw)
            self.assertTrue(loaded.history_enabled)
            self.assertFalse(loaded.providers["abuseipdb"])
            self.assertEqual(loaded.api_keys["virustotal"], "vt")

    def test_malformed_json_falls_back_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_settings = Path(tmpdir) / "settings.json"
            temp_settings.write_text("{broken-json", encoding="utf-8")
            with patch("src.desktop_services._SETTINGS_FILE", temp_settings):
                loaded = load_persisted_settings()
            self.assertEqual(loaded.api_keys["virustotal"], "")
            self.assertTrue(loaded.providers["virustotal"])
            self.assertFalse(loaded.history_enabled)

    def test_save_failure_returns_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_settings = Path(tmpdir) / "missing_dir" / "settings.json"
            settings = SessionSettings()
            with patch("src.desktop_services._SETTINGS_FILE", temp_settings):
                save_ok = save_persisted_settings(settings)
            self.assertFalse(save_ok)

    def test_read_failure_falls_back_to_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_settings = Path(tmpdir) / "settings.json"
            temp_settings.write_text("{}", encoding="utf-8")
            with (
                patch("src.desktop_services._SETTINGS_FILE", temp_settings),
                patch("pathlib.Path.read_text", side_effect=OSError("read fail")),
            ):
                loaded = load_persisted_settings()
            self.assertEqual(loaded.api_keys["virustotal"], "")
            self.assertTrue(loaded.providers["virustotal"])
            self.assertFalse(loaded.history_enabled)


class SocExportTests(unittest.TestCase):
    def test_export_json_and_export_soc_csv_content(self) -> None:
        payload = {
            "summary": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "confidence": 0.88,
                "mapping_source": "rule",
                "entity_count": 1,
            },
            "result": {
                "entities": [{"type": "ipv4", "value": "8.8.8.8"}],
                "attack_mapping": [
                    {
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                        "confidence": 0.88,
                        "rationale": "Multiple failed login attempts",
                        "evidence_refs": ["failed login"],
                    }
                ],
                "epc": {"explain": "x", "plan": ["p1"], "checklist": ["c1", "c2"]},
                "audit": {"ioc_enrichment": [{"ioc": "8.8.8.8", "status": "clean"}]},
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "soc.json"
            csv_path = Path(tmpdir) / "soc.csv"
            export_json(str(json_path), payload)
            export_soc_csv(str(csv_path), payload)
            json_loaded = json.loads(json_path.read_text(encoding="utf-8"))
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(json_loaded, payload)
        self.assertTrue(any(row["section"] == "summary" and row["item"] == "technique_id" and row["value"] == "T1110" for row in rows))
        self.assertTrue(any(row["section"] == "entity" and row["item"] == "1:ipv4" and row["value"] == "8.8.8.8" for row in rows))
        self.assertTrue(any(row["section"] == "mitre" and row["item"] == "1:T1110" and "failed login" in row["value"] for row in rows))

    def test_export_soc_csv_with_minimal_valid_payload_does_not_crash(self) -> None:
        minimal_payload = {
            "summary": {},
            "result": {"entities": [], "attack_mapping": [], "epc": {}, "audit": {}},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "soc_min.csv"
            export_soc_csv(str(csv_path), minimal_payload)
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
        self.assertTrue(all(set(row.keys()) == {"section", "item", "value"} for row in rows))

    def test_export_soc_csv_uses_partial_result_when_result_missing(self) -> None:
        payload = {
            "ok": False,
            "summary": {
                "technique_id": "N/A",
                "technique_name": "Not mapped",
                "confidence": 0.0,
                "mapping_source": "none",
                "entity_count": 1,
            },
            "partial_result": {
                "entities": [{"type": "username", "value": "alice"}],
                "attack_mapping": [],
                "epc": {},
                "audit": {
                    "mapping_source": "none",
                    "entity_count": 1,
                    "mapping_count": 0,
                    "ioc_enrichment": [{"ioc": "10.0.0.5", "status": "clean"}],
                },
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "soc_partial.csv"
            export_soc_csv(str(csv_path), payload)
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
        self.assertTrue(any(row["section"] == "summary" and row["item"] == "technique_id" and row["value"] == "N/A" for row in rows))
        self.assertTrue(any(row["section"] == "entity" and row["item"] == "1:username" and row["value"] == "alice" for row in rows))
        self.assertTrue(
            any(
                row["section"] == "ioc_enrichment"
                and row["item"] == "1:10.0.0.5"
                and row["value"] == "clean"
                for row in rows
            )
        )

    def test_export_soc_csv_handles_analyze_no_mapping_partial_result_payload(self) -> None:
        payload = analyze_soc_log(
            "authentication failed user=alice src_ip=10.0.0.5 domain=evil.example.com",
            enrich_iocs=True,
        )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload.get("reason"), "no_mapping")
        self.assertIsInstance(payload.get("partial_result"), dict)

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "soc_partial_from_wrapper.csv"
            export_soc_csv(str(csv_path), payload)
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertTrue(
            any(
                row["section"] == "summary"
                and row["item"] == "technique_id"
                and row["value"] == "N/A"
                for row in rows
            )
        )
        self.assertTrue(
            any(
                row["section"] == "entity"
                and row["item"] == "1:username"
                and row["value"] == "alice"
                for row in rows
            )
        )


class PackagingSensitivePathTests(unittest.TestCase):
    def setUp(self) -> None:
        self._original_cache = pipeline_module._IOC_MODULE_CACHE
        pipeline_module._IOC_MODULE_CACHE = None

    def tearDown(self) -> None:
        pipeline_module._IOC_MODULE_CACHE = self._original_cache

    def test_ioc_enrichment_search_paths_env_and_frozen_handling(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_dir = Path(tmpdir) / "env_ioc"
            env_dir.mkdir(parents=True, exist_ok=True)
            meipass_dir = Path(tmpdir) / "meipass"
            frozen_src = meipass_dir / "AIO_security_App_New" / "src"
            frozen_src.mkdir(parents=True, exist_ok=True)
            with (
                patch.dict(os.environ, {"SOC_IOC_ENRICHMENT_PATH": str(env_dir)}, clear=False),
                patch.object(pipeline_module.sys, "frozen", True, create=True),
                patch.object(pipeline_module.sys, "_MEIPASS", str(meipass_dir), create=True),
            ):
                paths = _ioc_enrichment_search_paths()
        self.assertIn(env_dir, paths)
        self.assertIn(frozen_src, paths)
        self.assertLess(paths.index(env_dir), paths.index(frozen_src))

    def test_load_ioc_enrichment_module_uses_cache(self) -> None:
        sentinel = object()
        pipeline_module._IOC_MODULE_CACHE = sentinel
        with patch("src.pipeline.importlib.import_module", side_effect=AssertionError("should not import")):
            loaded = pipeline_module._load_ioc_enrichment_module()
        self.assertIs(loaded, sentinel)

    def test_load_ioc_enrichment_module_missing_is_safe(self) -> None:
        pipeline_module._IOC_MODULE_CACHE = None
        with (
            patch("src.pipeline._ioc_enrichment_search_paths", return_value=[]),
            patch("src.pipeline.importlib.import_module", side_effect=ModuleNotFoundError("missing")),
        ):
            loaded = pipeline_module._load_ioc_enrichment_module()
        self.assertIsNone(loaded)

    def test_load_ioc_enrichment_module_search_path_fallback(self) -> None:
        pipeline_module._IOC_MODULE_CACHE = None
        fake_module = SimpleNamespace(scan_ioc=lambda *_args, **_kwargs: {})
        with tempfile.TemporaryDirectory() as tmpdir:
            search_path = Path(tmpdir) / "ioc_src"
            search_path.mkdir(parents=True, exist_ok=True)
            calls: list[str] = []

            def _import_side_effect(module_name: str) -> Any:
                calls.append(module_name)
                if module_name == "ioc_enrichment" and str(search_path) in sys.path:
                    return fake_module
                raise ModuleNotFoundError(module_name)

            with (
                patch("src.pipeline._ioc_enrichment_search_paths", return_value=[search_path]),
                patch("src.pipeline.importlib.import_module", side_effect=_import_side_effect),
            ):
                loaded = pipeline_module._load_ioc_enrichment_module()
        self.assertIs(loaded, fake_module)
        self.assertIs(pipeline_module._IOC_MODULE_CACHE, fake_module)
        self.assertIn("ioc_enrichment", calls)
        self.assertIn(str(search_path), sys.path)


class IocVerdictInScanTests(unittest.TestCase):
    def test_scan_iocs_rows_contain_verdict_fields(self) -> None:
        fake = _FakeIocModuleForScan()
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs(["8.8.8.8"], manual_ioc_type=None, providers=None, api_keys=None)
        self.assertEqual(len(rows), 1)
        self.assertIn("verdict", rows[0])
        self.assertIn("verdict_confidence", rows[0])
        self.assertIn("verdict_reasoning", rows[0])


class AppEntrySmokeTests(unittest.TestCase):
    def test_src_main_startup_path(self) -> None:
        class FakeApp:
            def __init__(self, _args: list[Any]) -> None:
                self.exec_called = 0
                self.style_requests: list[str] = []
                self.palette_set = 0

            def setStyle(self, name: str) -> None:  # noqa: N802 - Qt API
                self.style_requests.append(name)

            def setPalette(self, _palette: Any) -> None:  # noqa: N802 - Qt API
                self.palette_set += 1

            def exec(self) -> int:
                self.exec_called += 1
                return 0

        class FakeWindow:
            created = 0
            shown = 0

            def __init__(self) -> None:
                FakeWindow.created += 1

            def show(self) -> None:
                FakeWindow.shown += 1

        with (
            patch("src.desktop_app.QApplication", FakeApp),
            patch("src.desktop_app.DesktopSecurityApp", FakeWindow),
        ):
            from src.desktop_app import main

            code = main()
        self.assertEqual(code, 0)
        self.assertEqual(FakeWindow.created, 1)
        self.assertEqual(FakeWindow.shown, 1)

    def test_launcher_runs_main_in_main_context(self) -> None:
        with patch("src.desktop_app.main", return_value=0) as main_mock:
            with self.assertRaises(SystemExit) as exc:
                runpy.run_module("desktop_app", run_name="__main__")
        self.assertEqual(exc.exception.code, 0)
        main_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
