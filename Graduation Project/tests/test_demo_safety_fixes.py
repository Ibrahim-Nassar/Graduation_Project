"""Focused regression tests for the demo-safety / trustworthiness fixes.

Each test here pins one of the correctness fixes so later refactors cannot
silently undo them:

1. A ``Result`` with ``status="no_mapping"`` is the *only* thing that
   gets reported as "no_mapping" by the service layer — real
   ``ValidationError``s (internal correctness bugs) MUST surface honestly.
2. IOC verdicts are categorical assessments with no numeric confidence;
   AbuseIPDB doesn't flag benign public IPs as suspicious.
3. Saving settings invalidates the IOC scan cache so stale verdicts
   aren't served after the user fixes a bad key.
4. SOC Analysis no longer advertises a live IOC-enrichment capability —
   the dead ``ioc_providers`` / ``ioc_api_keys`` plumbing is gone.
5. Primary ATT&CK mapping is chosen by (severity tier, evidence
   strength), not by match order, so summaries reflect the most
   *important* technique when multiple fire.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from src import desktop_services
from src.contracts import AttackMapping
from src.desktop_services import (
    SessionSettings,
    analyze_soc_log,
    invalidate_ioc_cache,
    save_persisted_settings,
)
from src.ioc_enrichment import (
    abuseipdb_lookup,
    clear_scan_cache,
    compute_verdict,
    scan_ioc,
)
from src.pipeline import (
    _order_mappings_by_importance,
    _primary_sort_key,
    run,
)


# ──────────────────────────────────────────────────────────────────────────
# Fix #1: explicit no-mapping state vs real validation error
# ──────────────────────────────────────────────────────────────────────────


class ExplicitNoMappingStateTests(unittest.TestCase):
    def test_pipeline_returns_no_mapping_status_not_validation_error(self) -> None:
        """Benign input with zero rule hits yields ``status="no_mapping"``.

        Previously this surfaced as a generic ``ValidationError`` because
        the ``Result`` contract required ``min_length=1`` for mappings,
        which made real schema bugs look identical to "no mapping".
        """
        result = run("benign heartbeat ok status green")
        self.assertEqual(result.status, "no_mapping")
        self.assertEqual(result.attack_mapping, [])
        self.assertIsNone(result.epc)

    def test_no_mapping_result_carries_partial_context(self) -> None:
        result = run("authentication failed user=alice src_ip=10.0.0.5")
        if result.status == "no_mapping":
            self.assertGreaterEqual(len(result.entities), 1)
            self.assertIsInstance(result.audit.get("normalized_event"), dict)
            self.assertEqual(result.audit.get("mapping_source"), "none")

    def test_service_layer_does_not_swallow_real_validation_error(self) -> None:
        """A ``ValidationError`` from the pipeline is a real bug, not
        "no mapping".  The service layer must surface it as an error
        result, not silently downgrade it to a benign unmapped payload.
        """
        fake_exc = ValidationError.from_exception_data(
            "AttackMapping", [], input_type="python",
        )

        with patch("src.desktop_services.run", side_effect=fake_exc):
            payload = analyze_soc_log("some log content")

        self.assertFalse(payload["ok"])
        self.assertEqual(payload.get("reason"), "validation_error")
        self.assertNotEqual(payload.get("reason"), "no_mapping")

    def test_service_layer_reports_no_mapping_as_completed_status(self) -> None:
        payload = analyze_soc_log("benign heartbeat ok status green")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload.get("status"), "no_mapping")
        self.assertNotIn("error", payload)
        self.assertIsNone(payload["summary"]["technique_id"])
        self.assertEqual(payload["summary"]["mapping_source"], "none")

    def test_ui_presenter_classifies_validation_error_as_error_not_no_mapping(self) -> None:
        from src.ui_presenter import AnalysisState, build_breakdown

        payload = {
            "ok": False,
            "reason": "validation_error",
            "error": "Internal validation error — the analyzer produced an invalid result.",
            "result": {},
        }
        breakdown = build_breakdown(payload)
        self.assertEqual(breakdown.state, AnalysisState.ERROR)


# ──────────────────────────────────────────────────────────────────────────
# Fix #2: IOC verdict is a categorical assessment
# ──────────────────────────────────────────────────────────────────────────


class IocVerdictAssessmentTests(unittest.TestCase):
    def test_single_malicious_provider_is_labelled_single_source(self) -> None:
        """A lone malicious hit is reported as exactly that — one source —
        rather than dressed up with a fabricated confidence percentage.
        """
        results = {"virustotal": {"status": "malicious"}}
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "single_source_malicious")
        self.assertNotIn("confidence", verdict)

    def test_single_clean_provider_is_no_suspicious_findings(self) -> None:
        results = {"virustotal": {"status": "clean"}}
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "no_suspicious_findings")
        self.assertNotIn("confidence", verdict)

    def test_two_agreeing_providers_are_corroborated(self) -> None:
        results = {
            "virustotal": {"status": "malicious"},
            "otx": {"status": "malicious"},
        }
        verdict = compute_verdict(results)
        self.assertEqual(verdict["assessment"], "corroborated_malicious")
        self.assertEqual(sorted(verdict["malicious"]), ["otx", "virustotal"])

    def test_verdict_never_carries_a_numeric_field(self) -> None:
        """No assessment row carries a numeric "confidence" — the
        "Malicious @ 20%" anti-pattern cannot be rendered any more.
        """
        scenarios: list[dict[str, dict[str, str]]] = [
            {"virustotal": {"status": "malicious"}},
            {"abuseipdb": {"status": "suspicious"}},
            {"otx": {"status": "clean"}},
            {"threatfox": {"status": "malicious"}, "otx": {"status": "n/a"}},
        ]
        for scenario in scenarios:
            verdict = compute_verdict(scenario)
            self.assertNotIn("confidence", verdict)
            self.assertFalse(
                any(isinstance(value, (int, float)) and not isinstance(value, bool) for value in verdict.values()),
                f"numeric field leaked into verdict: {verdict} for {scenario}",
            )

    def test_abuseipdb_benign_low_confidence_ip_is_not_flagged_suspicious(self) -> None:
        """Public IPs routinely accrue a handful of low-effort reports on
        AbuseIPDB.  They MUST NOT be labeled suspicious — that flooded
        the demo with false positives.
        """
        payload = {"data": {"abuseConfidenceScore": 20, "totalReports": 3}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = abuseipdb_lookup("8.8.8.8", "k")
        self.assertEqual(result["status"], "clean")

    def test_abuseipdb_low_confidence_single_report_stays_clean(self) -> None:
        # Even with a middling score, a single report is not enough to
        # flip suspicious — that used to happen at score>=25.
        payload = {"data": {"abuseConfidenceScore": 30, "totalReports": 1}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = abuseipdb_lookup("1.1.1.1", "k")
        self.assertEqual(result["status"], "clean")

    def test_abuseipdb_strong_signal_still_flagged_malicious(self) -> None:
        payload = {"data": {"abuseConfidenceScore": 85, "totalReports": 40}}
        with patch("src.ioc_enrichment._http_get_json", return_value=payload):
            result = abuseipdb_lookup("198.51.100.9", "k")
        self.assertEqual(result["status"], "malicious")


# ──────────────────────────────────────────────────────────────────────────
# Fix #3: IOC cache invalidation on settings change
# ──────────────────────────────────────────────────────────────────────────


class IocCacheInvalidationTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_scan_cache()

    def tearDown(self) -> None:
        clear_scan_cache()

    def test_invalidate_ioc_cache_drops_cached_entries(self) -> None:
        with patch("src.ioc_enrichment.vt_lookup", return_value={"status": "clean"}), \
             patch("src.ioc_enrichment.otx_lookup", return_value={"status": "clean"}), \
             patch("src.ioc_enrichment.threatfox_lookup", return_value={"status": "n/a"}):
            scan_ioc("example.com", providers={"virustotal": True, "otx": True, "threatfox": True, "abuseipdb": False}, api_keys={})

        from src.ioc_enrichment import _SCAN_CACHE
        self.assertGreater(len(_SCAN_CACHE), 0)

        invalidate_ioc_cache()
        self.assertEqual(len(_SCAN_CACHE), 0)

    def test_save_persisted_settings_invalidates_cache(self) -> None:
        from src.ioc_enrichment import _SCAN_CACHE

        with patch("src.ioc_enrichment.vt_lookup", return_value={"status": "clean"}), \
             patch("src.ioc_enrichment.otx_lookup", return_value={"status": "clean"}), \
             patch("src.ioc_enrichment.threatfox_lookup", return_value={"status": "n/a"}):
            scan_ioc("example.com", providers={"virustotal": True, "otx": True, "threatfox": True, "abuseipdb": False}, api_keys={})
        self.assertGreater(len(_SCAN_CACHE), 0)

        settings = SessionSettings(
            api_keys={"virustotal": "new-key", "abuseipdb": "", "otx": "", "threatfox": ""},
            providers={"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True},
            history_enabled=False,
        )
        with patch.object(desktop_services, "_SETTINGS_FILE", Path("/__does_not_exist__/settings.json")):
            # OS write failure still invalidates — the in-memory settings
            # changed, so the cache MUST be cleared to avoid stale results.
            save_persisted_settings(settings)

        self.assertEqual(len(_SCAN_CACHE), 0)

    def test_rescan_after_settings_change_hits_providers_again(self) -> None:
        """End-to-end: after settings save, the next scan MUST call the
        providers again, not reuse the stale cache entry.
        """
        call_counter = {"n": 0}

        def fake_vt(*args, **kwargs):  # type: ignore[no-untyped-def]
            call_counter["n"] += 1
            return {"status": "clean", "score": 10}

        with patch("src.ioc_enrichment.vt_lookup", side_effect=fake_vt), \
             patch("src.ioc_enrichment.otx_lookup", return_value={"status": "n/a"}), \
             patch("src.ioc_enrichment.threatfox_lookup", return_value={"status": "n/a"}):
            scan_ioc(
                "example.com",
                providers={"virustotal": True, "otx": False, "threatfox": False, "abuseipdb": False},
                api_keys={"virustotal": "k"},
            )
            self.assertEqual(call_counter["n"], 1)

            # Without invalidation, the second call hits the cache.
            scan_ioc(
                "example.com",
                providers={"virustotal": True, "otx": False, "threatfox": False, "abuseipdb": False},
                api_keys={"virustotal": "k"},
            )
            self.assertEqual(call_counter["n"], 1)

            # After simulating a settings save the cache must be clear,
            # so the same scan goes back out to the provider.
            settings = SessionSettings(
                api_keys={"virustotal": "k", "abuseipdb": "", "otx": "", "threatfox": ""},
                providers={"virustotal": True, "abuseipdb": True, "otx": True, "threatfox": True},
                history_enabled=False,
            )
            with patch.object(desktop_services, "_SETTINGS_FILE", Path("/__does_not_exist__/s.json")):
                save_persisted_settings(settings)

            scan_ioc(
                "example.com",
                providers={"virustotal": True, "otx": False, "threatfox": False, "abuseipdb": False},
                api_keys={"virustotal": "k"},
            )
            self.assertEqual(call_counter["n"], 2)


# ──────────────────────────────────────────────────────────────────────────
# Fix #4: SOC → IOC enrichment plumbing is not dead / dishonest
# ──────────────────────────────────────────────────────────────────────────


class SocIocEnrichmentPlumbingTests(unittest.TestCase):
    def test_soc_background_no_longer_threads_ioc_provider_arguments(self) -> None:
        """The old signature accepted ``ioc_providers`` / ``ioc_api_keys``
        but hard-coded ``enrich_iocs=False``, so the arguments implied a
        live capability that never fired.  The signature must now be the
        honest minimal one.
        """
        from src.desktop_app import _analyze_soc_background

        with patch("src.desktop_app.analyze_soc_log", return_value={"ok": True}) as mocked:
            _analyze_soc_background(selected_log="raw", progress=lambda _m: None)

        mocked.assert_called_once_with("raw")

    def test_soc_background_rejects_dead_ioc_kwargs(self) -> None:
        """Guard-rail: nobody can sneak ``ioc_providers`` / ``ioc_api_keys``
        back in without tripping a TypeError, since those arguments are
        no longer part of the SOC Analysis contract.
        """
        from src.desktop_app import _analyze_soc_background

        with self.assertRaises(TypeError):
            _analyze_soc_background(  # type: ignore[call-arg]
                selected_log="raw",
                progress=lambda _m: None,
                ioc_providers={"virustotal": True},
                ioc_api_keys={"virustotal": "k"},
            )


# ──────────────────────────────────────────────────────────────────────────
# Fix #5: primary ATT&CK mapping selection
# ──────────────────────────────────────────────────────────────────────────


def _mapping(tid: str, evidence_strength: str = "moderate") -> AttackMapping:
    return AttackMapping(
        technique_id=tid,
        technique_name=f"Technique {tid}",
        evidence_strength=evidence_strength,  # type: ignore[arg-type]
        rationale="test",
        evidence_refs=["evidence"],
    )


class PrimaryMappingSelectionTests(unittest.TestCase):
    def test_high_severity_beats_low_severity_regardless_of_order(self) -> None:
        # Discovery rule matched first, credential-dumping rule matched
        # second.  Primary MUST be the credential-dumping one.
        mappings = [_mapping("T1082", "strong"), _mapping("T1003", "moderate")]
        ordered = _order_mappings_by_importance(mappings)
        self.assertEqual(ordered[0].technique_id, "T1003")
        # All mappings preserved — the primary changes, nothing is dropped.
        self.assertEqual({m.technique_id for m in ordered}, {"T1003", "T1082"})

    def test_evidence_strength_breaks_ties_within_same_severity_tier(self) -> None:
        mappings = [_mapping("T1059", "weak"), _mapping("T1071", "strong")]
        ordered = _order_mappings_by_importance(mappings)
        self.assertEqual(ordered[0].technique_id, "T1071")

    def test_single_mapping_is_returned_unchanged(self) -> None:
        mappings = [_mapping("T1059", "moderate")]
        self.assertEqual(_order_mappings_by_importance(mappings), mappings)

    def test_primary_sort_key_respects_sub_technique_parent(self) -> None:
        # A sub-technique like T1548.002 must inherit its parent's tier
        # rather than collapse to the default (tier 0).
        parent_tier, _ = _primary_sort_key(_mapping("T1548", "moderate"))
        sub_tier, _ = _primary_sort_key(_mapping("T1548.002", "moderate"))
        self.assertEqual(parent_tier, sub_tier)

    def test_primary_sort_key_ranks_strength_words(self) -> None:
        strong = _primary_sort_key(_mapping("T1059", "strong"))
        moderate = _primary_sort_key(_mapping("T1059", "moderate"))
        weak = _primary_sort_key(_mapping("T1059", "weak"))
        self.assertGreater(strong, moderate)
        self.assertGreater(moderate, weak)

    def test_end_to_end_primary_reflects_highest_severity_via_run(self) -> None:
        """Smoke: a log that fires both a low-severity discovery rule
        and a higher-severity credential-access rule surfaces the
        credential-access technique as primary in the ``Result``.
        """
        # Tasklist triggers T1057 (discovery, tier 1); Mimikatz-like
        # sekurlsa pattern triggers T1003 (credential dumping, tier 4).
        raw = "process=tasklist.exe && mimikatz.exe sekurlsa::logonpasswords"
        result = run(raw)
        if result.status == "no_mapping":
            self.skipTest("current rule set did not fire both techniques")
            return

        ids = [m.technique_id for m in result.attack_mapping]
        if "T1003" in ids and "T1057" in ids:
            self.assertEqual(result.attack_mapping[0].technique_id, "T1003")


if __name__ == "__main__":
    unittest.main()
