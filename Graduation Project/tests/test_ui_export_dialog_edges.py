from __future__ import annotations

import os
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from src.desktop_app import DesktopSecurityApp
from src.desktop_services import default_session_settings


class UiExportDialogEdgeTests(unittest.TestCase):
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

    def test_cancelled_ioc_json_save_dialog_does_not_export(self) -> None:
        self.window.last_ioc_rows = [{"ioc": "8.8.8.8", "raw": {}, "status": "clean"}]
        with (
            patch("src.desktop_app.QFileDialog.getSaveFileName", return_value=("", "")),
            patch("src.desktop_app.export_json") as export_json_mock,
            patch("src.desktop_app.QMessageBox.information") as info,
        ):
            self.window._export_ioc_json()
        export_json_mock.assert_not_called()
        info.assert_not_called()

    def test_cancelled_soc_csv_save_dialog_does_not_export(self) -> None:
        self.window.last_soc_payload = {"ok": True, "summary": {}, "result": {}}
        with (
            patch("src.desktop_app.QFileDialog.getSaveFileName", return_value=("", "")),
            patch("src.desktop_app.export_soc_csv") as export_soc_csv_mock,
            patch("src.desktop_app.QMessageBox.information") as info,
        ):
            self.window._export_soc_csv()
        export_soc_csv_mock.assert_not_called()
        info.assert_not_called()

    def test_cancelled_ioc_csv_save_dialog_does_not_export(self) -> None:
        self.window.last_ioc_rows = [{"ioc": "8.8.8.8", "status": "clean"}]
        with (
            patch("src.desktop_app.QFileDialog.getSaveFileName", return_value=("", "")),
            patch("src.desktop_app.export_ioc_csv") as export_ioc_csv_mock,
            patch("src.desktop_app.QMessageBox.information") as info,
        ):
            self.window._export_ioc_csv()
        export_ioc_csv_mock.assert_not_called()
        info.assert_not_called()

    def test_cancelled_soc_json_save_dialog_does_not_export(self) -> None:
        self.window.last_soc_payload = {"ok": True, "summary": {}, "result": {}}
        with (
            patch("src.desktop_app.QFileDialog.getSaveFileName", return_value=("", "")),
            patch("src.desktop_app.export_json") as export_json_mock,
            patch("src.desktop_app.QMessageBox.information") as info,
        ):
            self.window._export_soc_json()
        export_json_mock.assert_not_called()
        info.assert_not_called()

    def test_no_soc_payload_shows_info_and_does_not_export(self) -> None:
        self.window.last_soc_payload = None
        with (
            patch("src.desktop_app.QMessageBox.information") as info,
            patch("src.desktop_app.export_soc_csv") as export_soc_csv_mock,
            patch("src.desktop_app.export_json") as export_json_mock,
        ):
            self.window._export_soc_csv()
            self.window._export_soc_json()
        self.assertEqual(info.call_count, 2)
        export_soc_csv_mock.assert_not_called()
        export_json_mock.assert_not_called()

    def test_settings_save_failure_path_updates_status(self) -> None:
        self.window.api_key_inputs["virustotal"].setText("  key  ")
        self.window.history_toggle.setChecked(False)
        with patch("src.desktop_app.save_persisted_settings", return_value=False) as save_mock:
            self.window._apply_settings()
        save_mock.assert_called_once()
        self.assertIn("could not be saved to disk", self.window.settings_status_label.text().lower())


if __name__ == "__main__":
    unittest.main()
