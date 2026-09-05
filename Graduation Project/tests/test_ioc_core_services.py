from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from src.desktop_services import (
    _parse_csv_iocs,
    _parse_text_iocs,
    _unique_values,
    export_ioc_csv,
    export_json,
    scan_iocs,
)


class IocParsingAndDedupTests(unittest.TestCase):
    def test_parse_text_iocs_handles_newlines_commas_spaces_and_empty_lines(self) -> None:
        text = " 8.8.8.8 , example.com\n\nhttps://example.com/path\n  \n1.1.1.1,   "
        parsed = _parse_text_iocs(text)
        self.assertEqual(
            parsed,
            ["8.8.8.8", "example.com", "https://example.com/path", "1.1.1.1"],
        )

    def test_parse_csv_iocs_uses_preferred_column_and_ignores_empty(self) -> None:
        content = "ioc,notes\n8.8.8.8,first\n,blank\nexample.com,second\n"
        parsed = _parse_csv_iocs(content)
        self.assertEqual(parsed, ["8.8.8.8", "blank", "example.com"])

    def test_unique_values_removes_duplicates_case_insensitive_and_ignores_empty(self) -> None:
        values = ["8.8.8.8", "8.8.8.8", "Example.com", "example.com", "", "   ", "1.1.1.1"]
        deduped = _unique_values(values)
        self.assertEqual(deduped, ["8.8.8.8", "Example.com", "1.1.1.1"])


class _FakeIocModule:
    IOC_TYPE_IP = "ip"

    def __init__(self) -> None:
        self.scan_ioc_calls: list[tuple[str, dict[str, bool] | None, dict[str, str] | None]] = []
        self.vt_calls: list[tuple[str, str, str | None]] = []
        self.abuse_calls: list[tuple[str, str | None]] = []
        self.otx_calls: list[tuple[str, str, str | None]] = []
        self.threatfox_calls: list[tuple[str, str, str | None]] = []

    def detect_ioc_type(self, ioc: str) -> str:
        return "ip" if ioc.count(".") == 3 and "://" not in ioc else "domain"

    def scan_ioc(
        self,
        ioc: str,
        *,
        providers: dict[str, bool] | None = None,
        api_keys: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self.scan_ioc_calls.append((ioc, providers, api_keys))
        return {
            "ioc": ioc,
            "type": self.detect_ioc_type(ioc),
            "status": "clean",
            "score": 12,
            "providers": {
                "virustotal": {"status": "clean"},
                "abuseipdb": {"status": "clean"},
                "otx": {"status": "clean"},
                "threatfox": {"status": "clean"},
            },
            "errors": ["base_scan_error"],
        }

    def _enabled_providers(self, providers: dict[str, bool] | None) -> dict[str, bool]:
        defaults = {"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True}
        if providers is None:
            return defaults
        defaults.update({name: bool(value) for name, value in providers.items()})
        return defaults

    def _normalize_provider_result(
        self,
        provider_name: str,
        payload: dict[str, Any] | None,
        ioc: str,
        ioc_type: str,
    ) -> dict[str, Any]:
        output = dict(payload or {})
        output.setdefault("provider", provider_name)
        output.setdefault("ioc", ioc)
        output.setdefault("type", ioc_type)
        output.setdefault("status", "n/a")
        return output

    def _aggregate_status(self, provider_results: dict[str, dict[str, Any]]) -> str:
        statuses = {str((value or {}).get("status", "unknown")).lower() for value in provider_results.values()}
        if "malicious" in statuses:
            return "malicious"
        if "suspicious" in statuses:
            return "suspicious"
        if "clean" in statuses:
            return "clean"
        return "unknown"

    def _aggregate_score(self, provider_results: dict[str, dict[str, Any]]) -> int:
        mapping = {"malicious": 90, "suspicious": 65, "clean": 10, "unknown": 0, "n/a": 0}
        if not provider_results:
            return 0
        scores = [mapping.get(str((value or {}).get("status", "unknown")).lower(), 0) for value in provider_results.values()]
        return int(round(sum(scores) / len(scores)))

    def vt_lookup(self, ioc: str, ioc_type: str, api_key: str | None) -> dict[str, Any]:
        self.vt_calls.append((ioc, ioc_type, api_key))
        return {"status": "malicious", "error": "timeout"}

    def abuseipdb_lookup(self, ioc: str, api_key: str | None) -> dict[str, Any]:
        self.abuse_calls.append((ioc, api_key))
        return {"status": "clean"}

    def otx_lookup(self, ioc: str, ioc_type: str, api_key: str | None) -> dict[str, Any]:
        self.otx_calls.append((ioc, ioc_type, api_key))
        return {"status": "suspicious"}

    def threatfox_lookup(self, ioc: str, ioc_type: str, api_key: str | None) -> dict[str, Any]:
        self.threatfox_calls.append((ioc, ioc_type, api_key))
        return {"status": "not_found"}


class IocScanOrchestrationTests(unittest.TestCase):
    def test_provider_disabled_in_non_forced_scan_results_in_na_status(self) -> None:
        import src.ioc_enrichment as real_module

        with (
            patch("src.desktop_services._load_ioc_module", return_value=real_module),
            patch("src.ioc_enrichment._http_get_json") as mocked_get,
            patch("src.ioc_enrichment._http_post_json") as mocked_post,
        ):
            rows = scan_iocs(
                ["8.8.8.8"],
                manual_ioc_type=None,
                providers={"virustotal": False, "abuseipdb": False, "otx": False, "threatfox": False},
                api_keys={},
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["virustotal"], "n/a")
        self.assertEqual(rows[0]["abuseipdb"], "n/a")
        self.assertEqual(rows[0]["otx"], "n/a")
        self.assertEqual(rows[0]["threatfox"], "n/a")
        mocked_get.assert_not_called()
        mocked_post.assert_not_called()

    def test_missing_api_keys_with_real_module_does_not_crash_and_returns_na_provider_statuses(self) -> None:
        import src.ioc_enrichment as real_module

        with (
            patch("src.desktop_services._load_ioc_module", return_value=real_module),
            patch("src.ioc_enrichment._http_get_json") as mocked_get,
            patch("src.ioc_enrichment._http_post_json") as mocked_post,
        ):
            rows = scan_iocs(
                ["8.8.8.8", "evil.example.com"],
                manual_ioc_type=None,
                providers={"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True},
                api_keys={},
            )
        mocked_get.assert_not_called()
        mocked_post.assert_not_called()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["virustotal"], "n/a")
        self.assertEqual(rows[0]["abuseipdb"], "n/a")
        self.assertEqual(rows[0]["otx"], "n/a")
        self.assertEqual(rows[0]["threatfox"], "n/a")
        self.assertEqual(rows[1]["abuseipdb"], "not_supported")

    def test_manual_type_override_uses_forced_type_path_and_provider_toggles(self) -> None:
        fake = _FakeIocModule()
        providers = {"virustotal": True, "abuseipdb": True, "otx": False, "threatfox": True}
        api_keys = {"virustotal": "vt-key", "abuseipdb": "ab-key", "otx": "otx-key", "threatfox": "tf-key"}
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs(
                ["example.com"],
                manual_ioc_type="domain",
                providers=providers,
                api_keys=api_keys,
            )

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["detected_type"], "domain")
        self.assertEqual(row["effective_type"], "domain")
        self.assertEqual(row["virustotal"], "malicious")
        self.assertEqual(row["otx"], "n/a")
        self.assertEqual(row["threatfox"], "not_found")
        self.assertEqual(row["abuseipdb"], "not_supported")
        self.assertEqual(fake.scan_ioc_calls, [])
        self.assertEqual(len(fake.vt_calls), 1)
        self.assertEqual(len(fake.otx_calls), 0)
        self.assertEqual(len(fake.threatfox_calls), 1)
        self.assertEqual(len(fake.abuse_calls), 0)

    def test_error_propagation_inside_row(self) -> None:
        fake = _FakeIocModule()
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs(
                ["8.8.8.8"],
                manual_ioc_type="ip",
                providers={"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True},
                api_keys={},
            )

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertGreaterEqual(int(row["error_count"]), 1)
        self.assertIn("virustotal: timeout", row["errors"])
        self.assertIn("virustotal:malicious", row["provider_summary"])

    def test_non_forced_path_uses_scan_ioc(self) -> None:
        fake = _FakeIocModule()
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs(
                ["8.8.8.8"],
                manual_ioc_type=None,
                providers={"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True},
                api_keys={"virustotal": "x"},
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(len(fake.scan_ioc_calls), 1)
        self.assertEqual(rows[0]["ioc"], "8.8.8.8")

    def test_multiple_iocs_preserve_order_and_errors_are_isolated(self) -> None:
        fake = _FakeIocModule()

        def _scan_ioc_with_isolated_error(
            ioc: str,
            *,
            providers: dict[str, bool] | None = None,
            api_keys: dict[str, str] | None = None,
        ) -> dict[str, Any]:
            fake.scan_ioc_calls.append((ioc, providers, api_keys))
            if ioc == "bad.example.com":
                return {
                    "ioc": ioc,
                    "type": "domain",
                    "status": "unknown",
                    "score": 0,
                    "providers": {
                        "virustotal": {"status": "error", "error": "timeout"},
                    },
                    "errors": ["scan failed"],
                }
            return {
                "ioc": ioc,
                "type": "domain",
                "status": "clean",
                "score": 10,
                "providers": {
                    "virustotal": {"status": "clean"},
                },
                "errors": [],
            }

        fake.scan_ioc = _scan_ioc_with_isolated_error  # type: ignore[method-assign]
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs(
                ["first.example.com", "bad.example.com", "third.example.com"],
                manual_ioc_type=None,
                providers={"virustotal": True, "abuseipdb": False, "otx": False, "threatfox": False},
                api_keys={},
            )
        self.assertEqual([row["ioc"] for row in rows], ["first.example.com", "bad.example.com", "third.example.com"])
        self.assertEqual(rows[0]["error_count"], 0)
        self.assertGreaterEqual(rows[1]["error_count"], 1)
        self.assertEqual(rows[2]["error_count"], 0)

    def test_empty_scan_input_returns_empty_rows(self) -> None:
        fake = _FakeIocModule()
        with patch("src.desktop_services._load_ioc_module", return_value=fake):
            rows = scan_iocs([], manual_ioc_type=None, providers=None, api_keys=None)
        self.assertEqual(rows, [])


class IocExportTests(unittest.TestCase):
    def test_export_json_writes_expected_content(self) -> None:
        payload = {"b": 1, "a": {"x": 2}}
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "ioc.json"
            export_json(str(out_path), payload)
            written = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(written, payload)

    def test_export_ioc_csv_writes_expected_columns_and_multiple_rows(self) -> None:
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
            },
            {
                "ioc": "example.com",
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
            },
        ]
        expected_columns = [
            "ioc",
            "assessment",
            "verdict_reasoning",
            "detected_type",
            "effective_type",
            "status",
            "skip_reason",
            "virustotal",
            "abuseipdb",
            "otx",
            "threatfox",
            "provider_summary",
            "error_count",
            "errors",
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "ioc.csv"
            export_ioc_csv(str(out_path), rows)
            with out_path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                written_rows = list(reader)

        self.assertEqual(reader.fieldnames, expected_columns)
        self.assertNotIn("verdict_confidence", reader.fieldnames)
        self.assertNotIn("score", reader.fieldnames)
        self.assertEqual(len(written_rows), 2)
        self.assertEqual(written_rows[0]["ioc"], "8.8.8.8")
        self.assertEqual(written_rows[1]["ioc"], "example.com")
        self.assertIn("virustotal: timeout", written_rows[1]["errors"])


if __name__ == "__main__":
    unittest.main()
