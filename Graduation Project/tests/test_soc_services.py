from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from src.desktop_services import _read_log_file_content, analyze_soc_log, load_soc_log_inputs
from src.pipeline import run


class AnalyzeSocLogWrapperTests(unittest.TestCase):
    def test_success_path_returns_ok_summary_and_result(self) -> None:
        payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertTrue(payload["ok"])
        self.assertIn("summary", payload)
        self.assertIn("result", payload)
        summary = payload["summary"]
        self.assertIn("technique_id", summary)
        self.assertIn("technique_name", summary)
        self.assertIn("confidence", summary)
        self.assertIn("mapping_source", summary)
        self.assertIn("entity_count", summary)
        self.assertEqual(summary["mapping_source"], "rule")

    def test_exception_path_returns_ok_false_and_error(self) -> None:
        with patch("src.desktop_services.run", side_effect=RuntimeError("boom")):
            payload = analyze_soc_log("powershell -enc QUJDRA==")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "boom")

    def test_no_rule_no_model_failure_is_handled(self) -> None:
        with self.assertRaises(ValidationError):
            run("benign activity with no indicators")
        payload = analyze_soc_log("benign activity with no indicators")
        self.assertFalse(payload["ok"])
        self.assertIn("No ATT&CK mapping could be produced", payload["error"])
        self.assertIn("details", payload)


class FileInputTests(unittest.TestCase):
    def test_load_soc_log_inputs_uses_raw_text_when_no_file(self) -> None:
        output = load_soc_log_inputs("  raw log text  ", None)
        self.assertEqual(output, "raw log text")

    def test_read_log_file_content_json_raw_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "event.json"
            path.write_text('{"raw_log": "json raw log value", "other": 1}', encoding="utf-8")
            output = _read_log_file_content(str(path))
        self.assertEqual(output, "json raw log value")

    def test_read_log_file_content_plain_text_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "event.log"
            path.write_text("plain text log line", encoding="utf-8")
            output = _read_log_file_content(str(path))
        self.assertEqual(output, "plain text log line")

    def test_load_soc_log_inputs_with_file_path_reads_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "event.log"
            path.write_text(" file text value ", encoding="utf-8")
            output = load_soc_log_inputs("raw text", str(path))
        self.assertEqual(output, "file text value")

    def test_load_soc_log_inputs_prefers_file_over_raw_text_when_file_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "event.log"
            path.write_text("file wins", encoding="utf-8")
            output = load_soc_log_inputs("raw should not win", str(path))
        self.assertEqual(output, "file wins")


if __name__ == "__main__":
    unittest.main()
