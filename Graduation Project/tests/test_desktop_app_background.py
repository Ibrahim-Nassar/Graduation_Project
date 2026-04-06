from __future__ import annotations

import unittest
from unittest.mock import patch

from src.desktop_app import (
    _analyze_soc_background,
    _format_ioc_detail_text,
    _format_provider_summary,
    _scan_iocs_background,
    _status_tone,
)


class DesktopBackgroundTaskTests(unittest.TestCase):
    def test_scan_iocs_background_reports_progress_and_accumulates_rows(self) -> None:
        progress_messages: list[str] = []
        captured_calls: list[list[str]] = []

        def fake_scan_iocs(
            iocs: list[str],
            *,
            manual_ioc_type: str | None,
            providers: dict[str, bool],
            api_keys: dict[str, str],
        ) -> list[dict[str, str]]:
            captured_calls.append(iocs)
            self.assertEqual(manual_ioc_type, "ip")
            self.assertEqual(providers, {"virustotal": True})
            self.assertEqual(api_keys, {"virustotal": "abc"})
            return [{"ioc": iocs[0], "status": "clean"}]

        with patch("src.desktop_app.scan_iocs", side_effect=fake_scan_iocs):
            rows = _scan_iocs_background(
                iocs=["1.1.1.1", "8.8.8.8"],
                manual_ioc_type="ip",
                providers={"virustotal": True},
                api_keys={"virustotal": "abc"},
                progress=progress_messages.append,
            )

        self.assertEqual(captured_calls, [["1.1.1.1"], ["8.8.8.8"]])
        self.assertEqual(
            progress_messages,
            ["Scanning IOC 1 of 2...", "Scanning IOC 2 of 2..."],
        )
        self.assertEqual(
            rows,
            [
                {"ioc": "1.1.1.1", "status": "clean"},
                {"ioc": "8.8.8.8", "status": "clean"},
            ],
        )

    def test_analyze_soc_background_reports_status_and_returns_payload(self) -> None:
        progress_messages: list[str] = []
        expected_payload = {"ok": True, "summary": {"technique_id": "T1059"}}

        with patch("src.desktop_app.analyze_soc_log", return_value=expected_payload) as mocked:
            payload = _analyze_soc_background(
                selected_log="raw-log",
                model_path="",
                enrich_iocs=True,
                ioc_providers={"virustotal": False},
                ioc_api_keys={"virustotal": "abc"},
                progress=progress_messages.append,
            )

        mocked.assert_called_once_with(
            "raw-log",
            model_path="",
            enrich_iocs=True,
            ioc_providers={"virustotal": False},
            ioc_api_keys={"virustotal": "abc"},
        )
        self.assertEqual(progress_messages, ["Analyzing log with enrichment..."])
        self.assertEqual(payload, expected_payload)

    def test_status_tone_uses_expected_color_semantics(self) -> None:
        self.assertEqual(_status_tone("clean"), ("CLEAN", "#22C55E"))
        self.assertEqual(_status_tone("suspicious"), ("SUSPICIOUS", "#F59E0B"))
        self.assertEqual(_status_tone("malicious"), ("MALICIOUS", "#EF4444"))
        self.assertEqual(_status_tone("unknown"), ("UNKNOWN", "#9CA3AF"))

    def test_provider_summary_formatting_is_readable(self) -> None:
        self.assertEqual(
            _format_provider_summary("virustotal:clean, otx:suspicious"),
            "virustotal:clean | otx:suspicious",
        )
        self.assertEqual(
            _format_provider_summary(""),
            "No provider summary available.",
        )

    def test_ioc_detail_text_contains_all_key_sections(self) -> None:
        detail = _format_ioc_detail_text(
            {
                "ioc": "1.1.1.1",
                "detected_type": "ip",
                "effective_type": "ip",
                "status": "suspicious",
                "score": 42,
                "virustotal": "clean",
                "abuseipdb": "suspicious",
                "otx": "n/a",
                "threatfox": "not_found",
                "provider_summary": "virustotal:clean, abuseipdb:suspicious",
                "errors": ["abuseipdb: timeout"],
            },
        )
        self.assertIn("IOC: 1.1.1.1", detail)
        self.assertIn("Provider Statuses:", detail)
        self.assertIn("- abuseipdb: suspicious", detail)
        self.assertIn("Errors:", detail)
        self.assertIn("- abuseipdb: timeout", detail)


if __name__ == "__main__":
    unittest.main()
