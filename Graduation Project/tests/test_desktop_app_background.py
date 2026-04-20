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

        self.assertEqual(sorted(captured_calls), [["1.1.1.1"], ["8.8.8.8"]])
        self.assertEqual(len(progress_messages), 2)
        self.assertTrue(all("of 2" in m for m in progress_messages))
        iocs_in_result = sorted(r["ioc"] for r in rows)
        self.assertEqual(iocs_in_result, ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(len(rows), 2)

    def test_analyze_soc_background_reports_status_and_returns_payload(self) -> None:
        progress_messages: list[str] = []
        expected_payload = {"ok": True, "summary": {"technique_id": "T1059"}}

        with patch("src.desktop_app.analyze_soc_log", return_value=expected_payload) as mocked:
            payload = _analyze_soc_background(
                selected_log="raw-log",
                progress=progress_messages.append,
            )

        # SOC Analysis does not thread IOC provider settings down — IOC
        # enrichment lives on the dedicated IOC Scanner page.  Verify the
        # call contract is the minimal one and no dead arguments slip back.
        mocked.assert_called_once_with("raw-log")
        self.assertEqual(progress_messages, ["Analyzing log..."])
        self.assertEqual(payload, expected_payload)

    def test_status_tone_uses_expected_color_semantics(self) -> None:
        # Semantic colours are pulled from the palette tokens so the test
        # stays in sync with the shared design system. The specific hexes
        # are part of the design, not the contract.
        from src.desktop_app import _ACCENT, _DANGER, _TEXT2, _WARNING

        self.assertEqual(_status_tone("clean"), ("CLEAN", _ACCENT))
        self.assertEqual(_status_tone("suspicious"), ("SUSPICIOUS", _WARNING))
        self.assertEqual(_status_tone("malicious"), ("MALICIOUS", _DANGER))
        self.assertEqual(_status_tone("unknown"), ("UNKNOWN", _TEXT2))
        self.assertEqual(_status_tone("auth_error"), ("BAD API KEY", "#F97316"))

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
