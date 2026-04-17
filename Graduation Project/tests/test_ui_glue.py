from __future__ import annotations

import os
import unittest
from typing import Any
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from src.desktop_app import DesktopSecurityApp
from src.desktop_services import SessionSettings, default_session_settings


class _FakeSignal:
    def __init__(self) -> None:
        self._callbacks: list[Any] = []

    def connect(self, callback: Any) -> None:
        self._callbacks.append(callback)

    def emit(self, *args: Any, **kwargs: Any) -> None:
        for callback in self._callbacks:
            callback(*args, **kwargs)


class _FakeThread:
    instances: list["_FakeThread"] = []

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.started = _FakeSignal()
        self.finished = _FakeSignal()
        self._running = False
        self.started_called = False
        _FakeThread.instances.append(self)

    def isRunning(self) -> bool:
        return self._running

    def start(self) -> None:
        self.started_called = True
        self._running = True

    def quit(self) -> None:
        self._running = False

    def deleteLater(self) -> None:
        return


class _FakeWorker:
    instances: list["_FakeWorker"] = []

    def __init__(self, task: Any, *, task_kwargs: dict[str, Any]) -> None:
        self.task = task
        self.task_kwargs = task_kwargs
        self.progress = _FakeSignal()
        self.finished = _FakeSignal()
        self.failed = _FakeSignal()
        self.thread: _FakeThread | None = None
        _FakeWorker.instances.append(self)

    def moveToThread(self, thread: _FakeThread) -> None:
        self.thread = thread

    def run(self) -> None:
        return

    def deleteLater(self) -> None:
        return


class _BaseUiGlueTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.load_settings_patcher = patch(
            "src.desktop_app.load_persisted_settings",
            return_value=default_session_settings(),
        )
        self.load_settings_patcher.start()
        self.addCleanup(self.load_settings_patcher.stop)
        self.window = DesktopSecurityApp()

    def tearDown(self) -> None:
        self.window.close()
        _FakeThread.instances.clear()
        _FakeWorker.instances.clear()


class MainWindowTabSmokeTests(_BaseUiGlueTest):
    def test_window_instantiates_and_core_pages_exist(self) -> None:
        self.assertIsNotNone(self.window)
        self.assertGreaterEqual(self.window._stack.count(), 4)
        self.assertEqual(self.window.tab_index_home, 0)
        self.assertEqual(self.window.tab_index_ioc, 1)
        self.assertEqual(self.window.tab_index_soc, 2)
        self.assertEqual(self.window.tab_index_settings, 3)
        self.assertIsNotNone(self.window.ioc_table)
        self.assertIsNotNone(self.window.soc_entities_table)
        self.assertIsNotNone(self.window.provider_checkboxes)

    def test_no_cases_page_exists(self) -> None:
        self.assertFalse(hasattr(self.window, "tab_index_cases"))

    def test_soc_page_does_not_expose_model_path_input(self) -> None:
        self.assertFalse(hasattr(self.window, "soc_model_path_input"))


class IocRunHandlerTests(_BaseUiGlueTest):
    def test_empty_input_shows_warning_and_does_not_start_worker(self) -> None:
        with (
            patch("src.desktop_app.collect_iocs", return_value=[]),
            patch("src.desktop_app.QMessageBox.warning") as warning,
            patch("src.desktop_app.QThread", _FakeThread),
            patch("src.desktop_app._BackgroundTaskWorker", _FakeWorker),
        ):
            self.window._run_ioc_scan()
        warning.assert_called_once()
        self.assertEqual(len(_FakeWorker.instances), 0)
        self.assertIsNone(self.window._ioc_thread)

    def test_valid_single_ioc_starts_scan_path(self) -> None:
        self.window.ioc_single_input.setText("8.8.8.8")
        with (
            patch("src.desktop_app.collect_iocs", return_value=["8.8.8.8"]) as collect,
            patch("src.desktop_app.QThread", _FakeThread),
            patch("src.desktop_app._BackgroundTaskWorker", _FakeWorker),
        ):
            self.window._run_ioc_scan()
        collect.assert_called_once()
        self.assertEqual(len(_FakeWorker.instances), 1)
        self.assertEqual(_FakeWorker.instances[0].task_kwargs["iocs"], ["8.8.8.8"])
        self.assertTrue(_FakeThread.instances[0].started_called)

    def test_bulk_ioc_input_starts_scan_path(self) -> None:
        self.window.ioc_bulk_input.setPlainText("8.8.8.8\n1.1.1.1")
        with (
            patch("src.desktop_app.collect_iocs", return_value=["8.8.8.8", "1.1.1.1"]) as collect,
            patch("src.desktop_app.QThread", _FakeThread),
            patch("src.desktop_app._BackgroundTaskWorker", _FakeWorker),
        ):
            self.window._run_ioc_scan()
        self.assertEqual(collect.call_args.kwargs["bulk_text"], "8.8.8.8\n1.1.1.1")
        self.assertEqual(_FakeWorker.instances[0].task_kwargs["iocs"], ["8.8.8.8", "1.1.1.1"])

    def test_file_path_input_starts_scan_path(self) -> None:
        self.window.ioc_file_path = "C:/tmp/iocs.txt"
        with (
            patch("src.desktop_app.collect_iocs", return_value=["8.8.8.8"]) as collect,
            patch("src.desktop_app.QThread", _FakeThread),
            patch("src.desktop_app._BackgroundTaskWorker", _FakeWorker),
        ):
            self.window._run_ioc_scan()
        self.assertEqual(collect.call_args.kwargs["file_path"], "C:/tmp/iocs.txt")
        self.assertEqual(_FakeWorker.instances[0].task_kwargs["iocs"], ["8.8.8.8"])


class IocFinishHandlerTests(_BaseUiGlueTest):
    def test_finish_handler_populates_table_summary_and_detail(self) -> None:
        rows = [
            {
                "ioc": "8.8.8.8",
                "detected_type": "ip",
                "effective_type": "ip",
                "status": "clean",
                "score": 10,
                "virustotal": "clean",
                "abuseipdb": "clean",
                "otx": "clean",
                "threatfox": "not_found",
                "provider_summary": "virustotal:clean, abuseipdb:clean, otx:clean, threatfox:not_found",
                "error_count": 0,
                "errors": [],
                "raw": {},
            },
            {
                "ioc": "evil.example.com",
                "detected_type": "domain",
                "effective_type": "domain",
                "status": "suspicious",
                "score": 65,
                "virustotal": "suspicious",
                "abuseipdb": "not_supported",
                "otx": "suspicious",
                "threatfox": "suspicious",
                "provider_summary": "virustotal:suspicious, abuseipdb:not_supported, otx:suspicious, threatfox:suspicious",
                "error_count": 1,
                "errors": ["virustotal: timeout"],
                "raw": {},
            },
        ]
        self.window._on_ioc_scan_finished(rows)
        self.assertEqual(self.window.ioc_table.rowCount(), 2)
        self.assertIn("Total: 2", self.window.ioc_summary_label.text())
        self.assertIn("Malicious: 0", self.window.ioc_summary_label.text())
        summary_text = self.window.ioc_table.item(1, 11).text()
        self.assertIn("virustotal:suspicious", summary_text)
        self.assertIn("abuseipdb:not_supported", summary_text)
        self.assertEqual(self.window.ioc_table.item(1, 12).text(), "1")
        self.window.ioc_table.selectRow(1)
        self.window._update_ioc_detail_panel()
        self.assertIn("IOC: evil.example.com", self.window.ioc_detail_text.toPlainText())
        self.assertIn("Provider Statuses:", self.window.ioc_detail_text.toPlainText())

    def test_second_finish_render_replaces_previous_rows(self) -> None:
        first_rows = [
            {
                "ioc": "8.8.8.8",
                "detected_type": "ip",
                "effective_type": "ip",
                "status": "clean",
                "score": 10,
                "virustotal": "clean",
                "abuseipdb": "clean",
                "otx": "clean",
                "threatfox": "clean",
                "provider_summary": "virustotal:clean",
                "error_count": 0,
                "errors": [],
                "raw": {},
            }
        ]
        second_rows = [
            {
                "ioc": "evil.example.com",
                "detected_type": "domain",
                "effective_type": "domain",
                "status": "suspicious",
                "score": 65,
                "virustotal": "suspicious",
                "abuseipdb": "not_supported",
                "otx": "suspicious",
                "threatfox": "suspicious",
                "provider_summary": "virustotal:suspicious",
                "error_count": 1,
                "errors": ["timeout"],
                "raw": {},
            }
        ]
        self.window._on_ioc_scan_finished(first_rows)
        self.assertEqual(self.window.ioc_table.rowCount(), 1)
        self.assertEqual(self.window.ioc_table.item(0, 0).text(), "8.8.8.8")
        self.window._on_ioc_scan_finished(second_rows)
        self.assertEqual(self.window.ioc_table.rowCount(), 1)
        self.assertEqual(self.window.ioc_table.item(0, 0).text(), "evil.example.com")


class SocRunHandlerTests(_BaseUiGlueTest):
    def test_empty_input_shows_warning_and_does_not_start_worker(self) -> None:
        with (
            patch("src.desktop_app.load_soc_log_inputs", return_value=""),
            patch("src.desktop_app.QMessageBox.warning") as warning,
            patch("src.desktop_app.QThread", _FakeThread),
            patch("src.desktop_app._BackgroundTaskWorker", _FakeWorker),
        ):
            self.window._run_soc_analysis()
        warning.assert_called_once()
        self.assertEqual(len(_FakeWorker.instances), 0)
        self.assertIsNone(self.window._soc_thread)

    def test_raw_text_starts_analysis(self) -> None:
        self.window.soc_raw_log_input.setPlainText("failed login failed login failed login")
        with (
            patch("src.desktop_app.load_soc_log_inputs", return_value="failed login failed login failed login") as loader,
            patch("src.desktop_app.QThread", _FakeThread),
            patch("src.desktop_app._BackgroundTaskWorker", _FakeWorker),
        ):
            self.window._run_soc_analysis()
        loader.assert_called_once()
        self.assertEqual(_FakeWorker.instances[0].task_kwargs["selected_log"], "failed login failed login failed login")
        self.assertNotIn("model_path", _FakeWorker.instances[0].task_kwargs)
        self.assertTrue(_FakeThread.instances[0].started_called)

    def test_file_path_starts_analysis(self) -> None:
        self.window.soc_raw_log_input.setPlainText("raw text should be passed")
        self.window.soc_file_path = "C:/tmp/log.txt"
        with (
            patch("src.desktop_app.load_soc_log_inputs", return_value="failed login failed login failed login") as loader,
            patch("src.desktop_app.QThread", _FakeThread),
            patch("src.desktop_app._BackgroundTaskWorker", _FakeWorker),
        ):
            self.window._run_soc_analysis()
        self.assertEqual(loader.call_args.args[0], "raw text should be passed")
        self.assertEqual(loader.call_args.args[1], "C:/tmp/log.txt")
        self.assertEqual(_FakeWorker.instances[0].task_kwargs["selected_log"], "failed login failed login failed login")

    def test_enrich_toggle_changes_worker_args(self) -> None:
        self.window.soc_enrich_toggle.setChecked(True)
        with (
            patch("src.desktop_app.load_soc_log_inputs", return_value="failed login failed login failed login"),
            patch("src.desktop_app.QThread", _FakeThread),
            patch("src.desktop_app._BackgroundTaskWorker", _FakeWorker),
        ):
            self.window._run_soc_analysis()
        self.assertTrue(_FakeWorker.instances[0].task_kwargs["enrich_iocs"])


class SocFinishHandlerTests(_BaseUiGlueTest):
    def test_finish_handler_populates_soc_sections(self) -> None:
        payload = {
            "ok": True,
            "summary": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "confidence": 0.88,
                "mapping_source": "rule",
                "entity_count": 2,
            },
            "result": {
                "entities": [
                    {"type": "ipv4", "value": "8.8.8.8", "evidence_ref": "8.8.8.8", "start": 1, "end": 8},
                    {"type": "domain", "value": "evil.example.com", "evidence_ref": "evil.example.com", "start": 10, "end": 26},
                ],
                "attack_mapping": [
                    {
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                        "confidence": 0.88,
                        "rationale": "Multiple failed logins",
                        "evidence_refs": ["failed login"],
                    }
                ],
                "epc": {
                    "explain": "Explain text",
                    "plan": ["Step one", "Step two"],
                    "checklist": ["Item one", "Item two"],
                    "confidence": 0.88,
                    "citations": ["failed login"],
                },
                "audit": {
                    "mapping_source": "rule",
                    "ioc_enrichment": [
                        {
                            "ioc": "8.8.8.8",
                            "type": "ip",
                            "status": "clean",
                            "score": 10,
                            "providers": {},
                        }
                    ],
                },
            },
        }
        self.window.soc_enrich_toggle.setChecked(True)
        self.window._on_soc_analysis_finished(payload)
        self.assertEqual(self.window.soc_entities_table.rowCount(), 2)
        self.assertEqual(self.window.soc_mitre_table.rowCount(), 1)
        self.assertIn("Explain:", self.window.soc_epc_text.toPlainText())
        self.assertEqual(self.window.soc_enrichment_table.rowCount(), 1)
        self.assertIn("Mapped T1110 (Brute Force)", self.window.soc_summary_label.text())
        self.assertEqual(self.window.soc_top_source.text(), "Mapping Source: rule")
        self.assertIn("Used (1 IOCs)", self.window.soc_top_enrichment.text())

    def test_low_confidence_mapping_shows_cautionary_summary(self) -> None:
        payload = {
            "ok": True,
            "summary": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "confidence": 0.41,
                "mapping_source": "rule",
                "entity_count": 1,
            },
            "result": {
                "entities": [{"type": "ipv4", "value": "8.8.8.8", "evidence_ref": "8.8.8.8"}],
                "attack_mapping": [
                    {
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                        "confidence": 0.41,
                        "rationale": "Partial failed auth evidence",
                        "evidence_refs": ["authentication failed"],
                    }
                ],
                "epc": {
                    "explain": "Low-confidence mapping text",
                    "plan": ["Step one"],
                    "checklist": ["Item one", "Item two"],
                    "confidence": 0.41,
                    "citations": ["authentication failed"],
                },
                "audit": {"mapping_source": "rule"},
            },
        }
        self.window.soc_enrich_toggle.setChecked(False)
        self.window._on_soc_analysis_finished(payload)
        self.assertIn("low confidence", self.window.soc_summary_label.text().lower())
        self.assertIn("(low)", self.window.soc_top_confidence.text())
        self.assertIn("Not requested", self.window.soc_top_enrichment.text())

    def test_no_mapping_with_partial_extraction_is_explained(self) -> None:
        payload = {
            "ok": False,
            "error": "No ATT&CK mapping could be produced for this log.",
            "reason": "no_mapping",
            "partial_result": {
                "entities": [
                    {"type": "username", "value": "alice", "evidence_ref": "alice"},
                    {"type": "ipv4", "value": "10.0.0.5", "evidence_ref": "10.0.0.5"},
                ],
                "attack_mapping": [],
                "epc": {},
                "audit": {"mapping_source": "none", "entity_count": 2, "mapping_count": 0},
            },
        }
        self.window._on_soc_analysis_finished(payload)
        self.assertIn("no att&ck mapping was produced", self.window.soc_summary_label.text().lower())
        self.assertIn("extraction still succeeded", self.window.soc_summary_label.text().lower())
        self.assertEqual(self.window.soc_entities_table.rowCount(), 2)
        self.assertEqual(self.window.soc_mitre_table.rowCount(), 0)
        self.assertIn("unavailable because no ATT&CK mapping was produced", self.window.soc_epc_text.toPlainText())
        self.assertEqual(self.window.soc_top_source.text(), "Mapping Source: none")
        self.assertEqual(self.window.home_soc_metric.text(), "1")
        self.assertIn("Technique: N/A (Not mapped)", self.window.home_soc_summary.text())

    def test_enrichment_enabled_without_rows_is_called_out(self) -> None:
        payload = {
            "ok": True,
            "summary": {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "confidence": 0.9,
                "mapping_source": "rule",
                "entity_count": 1,
            },
            "result": {
                "entities": [{"type": "process", "value": "powershell.exe", "evidence_ref": "powershell"}],
                "attack_mapping": [
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "confidence": 0.9,
                        "rationale": "PowerShell encoded execution",
                        "evidence_refs": ["powershell", "-enc"],
                    }
                ],
                "epc": {
                    "explain": "Explain text",
                    "plan": ["Step one"],
                    "checklist": ["Item one", "Item two"],
                    "confidence": 0.9,
                    "citations": ["powershell"],
                },
                "audit": {"mapping_source": "rule", "ioc_enrichment": []},
            },
        }
        self.window.soc_enrich_toggle.setChecked(True)
        self.window._on_soc_analysis_finished(payload)
        self.assertIn("Enabled, but no IOC enrichment data was produced", self.window.soc_top_enrichment.text())


class AnalystBriefUiTests(_BaseUiGlueTest):
    def test_analyst_brief_widget_exists_on_soc_page(self) -> None:
        self.assertIsNotNone(self.window.soc_analyst_brief_label)
        self.assertTrue(self.window.soc_analyst_brief_label.wordWrap())

    def test_mapped_result_populates_brief_with_technique(self) -> None:
        payload = {
            "ok": True,
            "summary": {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "confidence": 0.9,
                "mapping_source": "rule",
                "entity_count": 1,
            },
            "analyst_brief": (
                "Log analysis identified activity involving process \u2018powershell.exe\u2019. "
                "Mapped to T1059 (Command and Scripting Interpreter) at 90% confidence. "
                "Primary evidence: PowerShell executed with encoded command switch. "
                "Recommended first action: Isolate the host."
            ),
            "result": {
                "entities": [{"type": "process", "value": "powershell.exe", "evidence_ref": "powershell"}],
                "attack_mapping": [
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "confidence": 0.9,
                        "rationale": "PowerShell executed with encoded command switch.",
                        "evidence_refs": ["powershell", "-enc"],
                    }
                ],
                "epc": {
                    "explain": "Explain text",
                    "plan": ["Isolate the host."],
                    "checklist": ["Item one", "Item two"],
                    "confidence": 0.9,
                    "citations": ["powershell"],
                },
                "audit": {"mapping_source": "rule"},
            },
        }
        self.window._on_soc_analysis_finished(payload)
        brief_text = self.window.soc_analyst_brief_label.text()
        self.assertIn("T1059", brief_text)
        self.assertIn("powershell", brief_text.lower())

    def test_no_mapping_result_populates_brief_without_technique(self) -> None:
        payload = {
            "ok": False,
            "error": "No ATT&CK mapping could be produced for this log.",
            "reason": "no_mapping",
            "analyst_brief": (
                "Analysis completed but no MITRE ATT&CK mapping was produced for this log. "
                "Extracted entities: username \u2018alice\u2019, ipv4 \u201810.0.0.5\u2019. "
                "Recommended action: review extracted fields for missing context,"
                " add correlated log lines, and re-analyze."
            ),
            "partial_result": {
                "entities": [
                    {"type": "username", "value": "alice", "evidence_ref": "alice"},
                    {"type": "ipv4", "value": "10.0.0.5", "evidence_ref": "10.0.0.5"},
                ],
                "attack_mapping": [],
                "epc": {},
                "audit": {"mapping_source": "none", "entity_count": 2, "mapping_count": 0},
            },
        }
        self.window._on_soc_analysis_finished(payload)
        brief_text = self.window.soc_analyst_brief_label.text()
        self.assertIn("no mitre att&ck mapping", brief_text.lower())
        self.assertIn("alice", brief_text)

    def test_brief_regenerated_when_not_in_payload(self) -> None:
        payload = {
            "ok": False,
            "error": "No ATT&CK mapping could be produced for this log.",
            "reason": "no_mapping",
            "partial_result": {
                "entities": [],
                "attack_mapping": [],
                "epc": {},
                "audit": {"mapping_source": "none", "entity_count": 0, "mapping_count": 0},
            },
        }
        self.window._on_soc_analysis_finished(payload)
        brief_text = self.window.soc_analyst_brief_label.text()
        self.assertIn("no mitre att&ck mapping", brief_text.lower())
        self.assertIn("Recommended action:", brief_text)


class SettingsApplyFlowTests(_BaseUiGlueTest):
    def test_sync_settings_to_ui_reflects_state(self) -> None:
        self.window.settings_state = SessionSettings(
            api_keys={
                "virustotal": " vt ",
                "abuseipdb": "",
                "otx": "otx-key",
                "threatfox": "",
            },
            providers={
                "virustotal": True,
                "abuseipdb": False,
                "otx": True,
                "threatfox": False,
            },
            history_enabled=True,
        )
        self.window._sync_settings_to_ui()
        self.assertTrue(self.window.provider_checkboxes["virustotal"].isChecked())
        self.assertFalse(self.window.provider_checkboxes["abuseipdb"].isChecked())
        self.assertEqual(self.window.api_key_inputs["virustotal"].text(), " vt ")
        self.assertFalse(self.window._history_nav_btn.isHidden())

    def test_apply_settings_saves_sanitized_keys_and_updates_history_visibility(self) -> None:
        self.window.api_key_inputs["virustotal"].setText("  vt-key  ")
        self.window.api_key_inputs["abuseipdb"].setText(" ")
        self.window.provider_checkboxes["abuseipdb"].setChecked(False)
        self.window.history_toggle.setChecked(True)
        with patch("src.desktop_app.save_persisted_settings", return_value=True) as save_mock:
            self.window._apply_settings()
        save_mock.assert_called_once()
        self.assertEqual(self.window.settings_state.api_keys["virustotal"], "vt-key")
        self.assertEqual(self.window.settings_state.api_keys["abuseipdb"], "")
        self.assertTrue(self.window.settings_state.history_enabled)
        self.assertFalse(self.window._history_nav_btn.isHidden())
        self.assertIn("saved and applied", self.window.settings_status_label.text().lower())

    def test_update_provider_key_status_labels(self) -> None:
        self.window.api_key_inputs["virustotal"].setText("x")
        self.window.api_key_inputs["abuseipdb"].setText("")
        self.window._update_provider_key_statuses()
        self.assertEqual(self.window.provider_key_status_labels["virustotal"].text(), "Key entered")
        self.assertEqual(self.window.provider_key_status_labels["abuseipdb"].text(), "Key missing")


class ExportButtonGlueTests(_BaseUiGlueTest):
    def test_no_ioc_data_shows_info_and_does_not_export(self) -> None:
        with (
            patch("src.desktop_app.QMessageBox.information") as info,
            patch("src.desktop_app.export_json") as export_json_mock,
        ):
            self.window._export_ioc_json()
        info.assert_called_once()
        export_json_mock.assert_not_called()

    def test_export_ioc_json_calls_export_with_selected_path(self) -> None:
        self.window.last_ioc_rows = [{"ioc": "8.8.8.8", "raw": {}, "status": "clean"}]
        with (
            patch("src.desktop_app.QFileDialog.getSaveFileName", return_value=("C:/tmp/ioc.json", "JSON Files (*.json)")),
            patch("src.desktop_app.export_json") as export_json_mock,
            patch("src.desktop_app.QMessageBox.information") as info,
        ):
            self.window._export_ioc_json()
        export_json_mock.assert_called_once()
        self.assertEqual(export_json_mock.call_args.args[0], "C:/tmp/ioc.json")
        info.assert_called_once()

    def test_export_ioc_csv_calls_export_with_selected_path(self) -> None:
        self.window.last_ioc_rows = [{"ioc": "8.8.8.8", "status": "clean"}]
        with (
            patch("src.desktop_app.QFileDialog.getSaveFileName", return_value=("C:/tmp/ioc.csv", "CSV Files (*.csv)")),
            patch("src.desktop_app.export_ioc_csv") as export_csv_mock,
            patch("src.desktop_app.QMessageBox.information") as info,
        ):
            self.window._export_ioc_csv()
        export_csv_mock.assert_called_once_with("C:/tmp/ioc.csv", self.window.last_ioc_rows)
        info.assert_called_once()

    def test_export_soc_json_calls_export_with_selected_path(self) -> None:
        self.window.last_soc_payload = {"ok": True}
        with (
            patch("src.desktop_app.QFileDialog.getSaveFileName", return_value=("C:/tmp/soc.json", "JSON Files (*.json)")),
            patch("src.desktop_app.export_json") as export_json_mock,
            patch("src.desktop_app.QMessageBox.information") as info,
        ):
            self.window._export_soc_json()
        export_json_mock.assert_called_once_with("C:/tmp/soc.json", self.window.last_soc_payload)
        info.assert_called_once()

    def test_no_soc_payload_shows_info_and_does_not_export(self) -> None:
        self.window.last_soc_payload = None
        with (
            patch("src.desktop_app.QMessageBox.information") as info,
            patch("src.desktop_app.export_json") as export_json_mock,
            patch("src.desktop_app.export_soc_csv") as export_soc_csv_mock,
        ):
            self.window._export_soc_json()
            self.window._export_soc_csv()
        self.assertEqual(info.call_count, 2)
        export_json_mock.assert_not_called()
        export_soc_csv_mock.assert_not_called()

    def test_export_soc_csv_calls_export_with_selected_path(self) -> None:
        self.window.last_soc_payload = {"ok": True}
        with (
            patch("src.desktop_app.QFileDialog.getSaveFileName", return_value=("C:/tmp/soc.csv", "CSV Files (*.csv)")),
            patch("src.desktop_app.export_soc_csv") as export_csv_mock,
            patch("src.desktop_app.QMessageBox.information") as info,
        ):
            self.window._export_soc_csv()
        export_csv_mock.assert_called_once_with("C:/tmp/soc.csv", self.window.last_soc_payload)
        info.assert_called_once()


class ErrorHandlingPathTests(_BaseUiGlueTest):
    def test_ioc_failure_handler_shows_message_and_keeps_ui_alive(self) -> None:
        with (
            patch("src.desktop_app.QMessageBox.warning") as warning,
            patch.object(self.window, "_set_ioc_loading") as set_loading,
        ):
            self.window._on_ioc_scan_failed("ioc failed")
        warning.assert_called_once()
        set_loading.assert_called_once_with(False)
        self.assertIn("ioc failed", self.window.ioc_summary_label.text().lower())

    def test_soc_failure_handler_shows_message_and_keeps_ui_alive(self) -> None:
        with (
            patch("src.desktop_app.QMessageBox.warning") as warning,
            patch.object(self.window, "_set_soc_loading") as set_loading,
        ):
            self.window._on_soc_analysis_failed("soc failed")
        warning.assert_called_once()
        set_loading.assert_called_once_with(False)
        self.assertIn("soc failed", self.window.soc_summary_label.text().lower())


if __name__ == "__main__":
    unittest.main()
