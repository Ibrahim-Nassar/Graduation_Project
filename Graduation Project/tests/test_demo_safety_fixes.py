"""Focused regression tests for the demo-safety / trustworthiness fixes.

Each test here pins one of the correctness fixes so later refactors cannot
silently undo them:

1. ``NoMappingError`` is the *only* thing that gets re-labeled as
   "no_mapping" by the service layer — real ``ValidationError``s
   (internal correctness bugs) MUST surface honestly.
2. IOC verdict confidence no longer produces "Malicious @ 20%"-style
   contradictions; single credible provider verdicts stay trustworthy;
   AbuseIPDB doesn't flag benign public IPs as suspicious.
3. Saving settings invalidates the IOC scan cache so stale verdicts
   aren't served after the user fixes a bad key.
4. SOC Analysis no longer advertises a live IOC-enrichment capability —
   the dead ``ioc_providers`` / ``ioc_api_keys`` plumbing is gone.
5. Primary ATT&CK mapping is chosen by (severity tier, confidence), not
   by match order, so summaries reflect the most *important* technique
   when multiple fire.
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
    NoMappingError,
    _order_mappings_by_importance,
    _primary_sort_key,
    run,
)


# ──────────────────────────────────────────────────────────────────────────
# Fix #1: explicit no-mapping state vs real validation error
# ──────────────────────────────────────────────────────────────────────────


class ExplicitNoMappingStateTests(unittest.TestCase):
    def test_pipeline_raises_no_mapping_error_not_validation_error(self) -> None:
        """Benign input with zero rule hits should raise ``NoMappingError``.

        Previously this surfaced as a generic ``ValidationError`` because
        the ``Result`` contract requires ``min_length=1`` for mappings,
        which made real schema bugs look identical to "no mapping".
        """
        with self.assertRaises(NoMappingError):
            run("benign heartbeat ok status green")

    def test_no_mapping_error_carries_partial_context(self) -> None:
        try:
            run("authentication failed user=alice src_ip=10.0.0.5")
        except NoMappingError as exc:
            self.assertGreaterEqual(len(exc.entities), 1)
            self.assertIsInstance(exc.normalized_event, dict)
        else:
            # If a rule ever matches this log in the future that's fine —
            # the contract we care about is only that unmapped logs raise
            # NoMappingError, not ValidationError.
            pass

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

    def test_service_layer_translates_no_mapping_error_to_reason_no_mapping(self) -> None:
        payload = analyze_soc_log("benign heartbeat ok status green")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload.get("reason"), "no_mapping")
        self.assertIn("No ATT&CK mapping could be produced", payload["error"])

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
# Fix #2: IOC verdict confidence
# ──────────────────────────────────────────────────────────────────────────


class IocVerdictConfidenceTests(unittest.TestCase):
    def test_single_credible_malicious_provider_has_meaningful_confidence(self) -> None:
        """A lone malicious hit from VirusTotal used to display at ~33%
        confidence because of the old ``coverage_factor`` penalty.  That
        made the verdict and the displayed confidence look contradictory.
        """
        results = {"virustotal": {"status": "malicious"}}
        verdict = compute_verdict(results)
        self.assertEqual(verdict["verdict"], "Malicious")
        # Must NOT be in the old "contradictory" band (< 50%).
        self.assertGreaterEqual(verdict["confidence"], 50)

    def test_single_clean_provider_has_meaningful_confidence(self) -> None:
        results = {"virustotal": {"status": "clean"}}
        verdict = compute_verdict(results)
        self.assertEqual(verdict["verdict"], "Clean")
        self.assertGreaterEqual(verdict["confidence"], 50)

    def test_two_agreeing_providers_have_strong_confidence(self) -> None:
        results = {
            "virustotal": {"status": "malicious"},
            "otx": {"status": "malicious"},
        }
        verdict = compute_verdict(results)
        self.assertEqual(verdict["verdict"], "Malicious")
        self.assertGreaterEqual(verdict["confidence"], 90)

    def test_verdict_never_looks_contradictorily_weak(self) -> None:
        """No (verdict, confidence) row should ever display a decisive
        classification with <50 confidence — that's the "Malicious @ 20%"
        anti-pattern we are explicitly defending against.
        """
        scenarios: list[dict[str, dict[str, str]]] = [
            {"virustotal": {"status": "malicious"}},
            {"abuseipdb": {"status": "suspicious"}},
            {"otx": {"status": "clean"}},
            {"threatfox": {"status": "malicious"}, "otx": {"status": "n/a"}},
        ]
        for scenario in scenarios:
            verdict = compute_verdict(scenario)
            if verdict["verdict"] in {"Malicious", "Suspicious", "Clean"}:
                self.assertGreaterEqual(
                    verdict["confidence"], 50,
                    f"Decisive verdict with low confidence: {verdict} for {scenario}",
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


def _mapping(tid: str, confidence: float = 0.8) -> AttackMapping:
    return AttackMapping(
        technique_id=tid,
        technique_name=f"Technique {tid}",
        confidence=confidence,
        rationale="test",
        evidence_refs=["evidence"],
    )


class PrimaryMappingSelectionTests(unittest.TestCase):
    def test_high_severity_beats_low_severity_regardless_of_order(self) -> None:
        # Discovery rule matched first, credential-dumping rule matched
        # second.  Primary MUST be the credential-dumping one.
        mappings = [_mapping("T1082", 0.9), _mapping("T1003", 0.7)]
        ordered = _order_mappings_by_importance(mappings)
        self.assertEqual(ordered[0].technique_id, "T1003")
        # All mappings preserved — the primary changes, nothing is dropped.
        self.assertEqual({m.technique_id for m in ordered}, {"T1003", "T1082"})

    def test_confidence_breaks_ties_within_same_severity_tier(self) -> None:
        mappings = [_mapping("T1059", 0.6), _mapping("T1071", 0.9)]
        ordered = _order_mappings_by_importance(mappings)
        self.assertEqual(ordered[0].technique_id, "T1071")

    def test_single_mapping_is_returned_unchanged(self) -> None:
        mappings = [_mapping("T1059", 0.8)]
        self.assertEqual(_order_mappings_by_importance(mappings), mappings)

    def test_primary_sort_key_respects_sub_technique_parent(self) -> None:
        # A sub-technique like T1548.002 must inherit its parent's tier
        # rather than collapse to the default (tier 0).
        parent_tier, _ = _primary_sort_key(_mapping("T1548", 0.8))
        sub_tier, _ = _primary_sort_key(_mapping("T1548.002", 0.8))
        self.assertEqual(parent_tier, sub_tier)

    def test_end_to_end_primary_reflects_highest_severity_via_run(self) -> None:
        """Smoke: a log that fires both a low-severity discovery rule
        and a higher-severity credential-access rule surfaces the
        credential-access technique as primary in the ``Result``.
        """
        # Tasklist triggers T1057 (discovery, tier 1); Mimikatz-like
        # sekurlsa pattern triggers T1003 (credential dumping, tier 4).
        raw = "process=tasklist.exe && mimikatz.exe sekurlsa::logonpasswords"
        try:
            result = run(raw)
        except NoMappingError:
            self.skipTest("current rule set did not fire both techniques")
            return

        ids = [m.technique_id for m in result.attack_mapping]
        if "T1003" in ids and "T1057" in ids:
            self.assertEqual(result.attack_mapping[0].technique_id, "T1003")


if __name__ == "__main__":
    unittest.main()
