"""Tests for the ML fallback ATT&CK suggester.

The fallback must:
  * stay out of the way when a deterministic rule already matched,
  * produce a labeled, probability-bearing suggestion only when confident,
  * keep "no mapping" when the classifier is unsure or the top-1/top-2
    margin is too narrow,
  * degrade gracefully when the model artifact is missing or broken, and
  * use a deterministic feature-text representation identical at training
    and inference time.
"""

from __future__ import annotations

import pickle
import unittest
from pathlib import Path
from unittest.mock import patch

from src import desktop_services
from src.desktop_app import _soc_banner
from src.desktop_services import _resolve_fallback_model, analyze_soc_log
from src.model import build_feature_text
from src.pipeline import (
    ML_FALLBACK_CONFIDENCE_THRESHOLD,
    ML_FALLBACK_MARGIN_THRESHOLD,
    _build_ml_fallback_mapping,
    run,
)


class _FakeProbabilities(list):
    def argmax(self) -> int:
        return int(max(range(len(self)), key=lambda idx: self[idx]))

    def __iter__(self):  # type: ignore[override]
        return super().__iter__()


class _FakeModel:
    """Minimal stand-in for a scikit-learn classifier pipeline.

    ``classes_`` mirrors sklearn's attribute so ``predict_attack`` can
    build the ranked-classes list the pipeline uses for soft-BENIGN
    fall-through.  Older tests that don't care about that behaviour can
    pass ``classes=None`` and fall back to numeric labels which the
    fallback code then ignores.
    """

    def __init__(
        self,
        label: str,
        probabilities: list[float],
        classes: list[str] | None = None,
    ) -> None:
        self._label = label
        self._probabilities = probabilities
        self.classes_ = classes if classes is not None else [""] * len(probabilities)
        self.predict_calls = 0
        self.predict_proba_calls = 0

    def predict(self, inputs: list[str]) -> list[str]:
        self.predict_calls += 1
        return [self._label for _ in inputs]

    def predict_proba(self, inputs: list[str]) -> list[_FakeProbabilities]:
        self.predict_proba_calls += 1
        return [_FakeProbabilities(self._probabilities) for _ in inputs]


class MlFallbackGatingTests(unittest.TestCase):
    def test_rule_hit_does_not_invoke_ml_model(self) -> None:
        # Unambiguous powershell-encoded rule hit -> the pipeline must never
        # touch the classifier, regardless of what the model would say.
        model = _FakeModel("T1071", [0.1, 0.9])
        result = run(
            "user=alice process=powershell.exe command_line='powershell -enc QUJDRA=='",
            model=model,
        )
        dump = result.model_dump(mode="json")
        self.assertEqual(dump["audit"]["mapping_source"], "rule")
        self.assertEqual(dump["attack_mapping"][0]["technique_id"], "T1059")
        self.assertEqual(model.predict_calls, 0)
        self.assertEqual(model.predict_proba_calls, 0)

    def test_confident_ml_prediction_is_surfaced_when_no_rule_matches(self) -> None:
        model = _FakeModel("T1105", [0.05, 0.95])
        result = run("some benign-looking log with no rule signatures", model=model)
        dump = result.model_dump(mode="json")
        self.assertEqual(dump["audit"]["mapping_source"], "ml_fallback")
        self.assertEqual(dump["attack_mapping"][0]["technique_id"], "T1105")
        # ML fallback output is always reported as weak evidence — the
        # classifier probability is never surfaced as a confidence value.
        self.assertEqual(dump["attack_mapping"][0]["evidence_strength"], "weak")
        self.assertNotIn("confidence", dump["attack_mapping"][0])
        self.assertEqual(model.predict_calls, 1)

    def test_low_confidence_ml_prediction_yields_no_mapping(self) -> None:
        # Below-threshold probabilities must not surface a weak guess; the
        # pipeline should keep "no mapping" and surface that state to the UI.
        weak = ML_FALLBACK_CONFIDENCE_THRESHOLD - 0.05
        weaker = max(0.0, ML_FALLBACK_CONFIDENCE_THRESHOLD - 0.15)
        model = _FakeModel("T1071", [weak, weaker])
        mapping = _build_ml_fallback_mapping(
            "log with nothing specific to match", model
        )
        self.assertIsNone(mapping)

    def test_ml_fallback_rationale_and_evidence_are_honest(self) -> None:
        model = _FakeModel("T1059", [0.1, 0.9])
        mapping = _build_ml_fallback_mapping("uncategorised event text", model)
        self.assertIsNotNone(mapping)
        assert mapping is not None
        self.assertEqual(mapping.technique_id, "T1059")
        self.assertIn("ML fallback", mapping.rationale)
        self.assertEqual(mapping.evidence_refs, ["ml_prediction"])


class ResolveFallbackModelTests(unittest.TestCase):
    def test_empty_path_never_loads_a_model(self) -> None:
        # There is no bundled default artifact: an empty path means "no ML
        # fallback", and nothing is auto-loaded from disk.
        self.assertFalse(hasattr(desktop_services, "DEFAULT_MODEL_PATH"))
        with patch("src.desktop_services.load_model") as load_mock:
            self.assertIsNone(_resolve_fallback_model(""))
            self.assertIsNone(_resolve_fallback_model("   "))
        load_mock.assert_not_called()

    def test_missing_explicit_artifact_returns_none(self) -> None:
        self.assertIsNone(_resolve_fallback_model(str(Path("nope.pkl"))))

    def test_corrupt_artifact_degrades_to_none(self, tmp_suffix: str = ".pkl") -> None:
        import tempfile

        with tempfile.NamedTemporaryFile(
            suffix=tmp_suffix, delete=False
        ) as handle:
            handle.write(b"not a pickle payload")
            path = Path(handle.name)
        try:
            self.assertIsNone(_resolve_fallback_model(str(path)))
        finally:
            path.unlink(missing_ok=True)

    def test_valid_pickle_with_wrong_type_returns_none(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as handle:
            pickle.dump({"not": "a classifier"}, handle)
            path = Path(handle.name)
        try:
            self.assertIsNone(_resolve_fallback_model(str(path)))
        finally:
            path.unlink(missing_ok=True)


class AnalyzeSocLogMlWiringTests(unittest.TestCase):
    def test_rule_hit_reports_rule_mapping_source_without_model(self) -> None:
        payload = analyze_soc_log(
            "user=alice process=powershell.exe command_line='powershell -enc QUJDRA=='"
        )
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "mapped")
        self.assertEqual(payload["summary"]["mapping_source"], "rule")
        self.assertEqual(payload["summary"]["technique_id"], "T1059")

    def test_no_rule_and_no_model_returns_no_mapping(self) -> None:
        # No model path → no ML fallback is loaded, so an unmatched log is
        # reported as a completed "no_mapping" analysis.
        payload = analyze_soc_log("benign heartbeat ok status green")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload.get("status"), "no_mapping")
        self.assertEqual(payload["summary"]["mapping_source"], "none")

    def test_no_rule_hit_surfaces_ml_fallback_when_model_available(self) -> None:
        fake_model = _FakeModel("T1071", [0.05, 0.95])
        with patch(
            "src.desktop_services._resolve_fallback_model",
            return_value=fake_model,
        ):
            payload = analyze_soc_log("obscure log with no rule trigger")
        self.assertTrue(payload["ok"])
        summary = payload["summary"]
        self.assertEqual(summary["mapping_source"], "ml_fallback")
        self.assertEqual(summary["technique_id"], "T1071")
        self.assertEqual(summary["evidence_strength"], "weak")
        self.assertNotIn("confidence", summary)


class MlFallbackMarginTests(unittest.TestCase):
    """Margin gate: close top-1/top-2 probabilities must suppress the prediction."""

    def test_narrow_margin_yields_no_mapping_even_above_threshold(self) -> None:
        # Construct a top-1 well above the confidence threshold but with a
        # top-1/top-2 gap strictly below ML_FALLBACK_MARGIN_THRESHOLD → the
        # fallback must still return None because the model is not
        # sufficiently differentiated between its top two classes.
        top1 = max(ML_FALLBACK_CONFIDENCE_THRESHOLD + 0.20, 0.50)
        narrow_gap = max(ML_FALLBACK_MARGIN_THRESHOLD - 0.01, 0.01)
        top2 = top1 - narrow_gap
        model = _FakeModel("T1059", [top2, top1])
        mapping = _build_ml_fallback_mapping(
            "some log text with no specific rule match", model
        )
        self.assertIsNone(mapping)

    def test_sufficient_margin_and_confidence_surfaces_prediction(self) -> None:
        # top-1 = 0.80, top-2 = 0.20, margin = 0.60 → both gates pass.
        model = _FakeModel("T1059", [0.20, 0.80])
        mapping = _build_ml_fallback_mapping(
            "some log text with no specific rule match", model
        )
        self.assertIsNotNone(mapping)
        assert mapping is not None
        self.assertEqual(mapping.technique_id, "T1059")

    def test_margin_threshold_constant_is_positive(self) -> None:
        self.assertGreater(ML_FALLBACK_MARGIN_THRESHOLD, 0.0)

    def test_confidence_threshold_is_reasonable_for_calibrated_model(self) -> None:
        # With the calibrated classifier (sigmoid calibration + balanced
        # class weights) in train_model v2, calibrated sigmoid scores are
        # much less inflated than the raw LogReg scores the previous
        # threshold (0.50) was tuned for.  The threshold must still be
        # meaningfully above chance (1 / n_classes for ~33 classes is ~0.03)
        # to prevent surfacing random guesses, but high enough values would
        # suppress the calibrated attack predictions that sit in the
        # 0.25-0.45 range.
        self.assertGreaterEqual(ML_FALLBACK_CONFIDENCE_THRESHOLD, 0.20)
        self.assertLess(ML_FALLBACK_CONFIDENCE_THRESHOLD, 0.60)


class MlFallbackBenignSuppressionTests(unittest.TestCase):
    """Benign sentinel: the model can predict BENIGN, and when it does the
    pipeline must not surface a mapping, regardless of confidence/margin."""

    def test_benign_prediction_returns_none_even_when_confident(self) -> None:
        model = _FakeModel("BENIGN", [0.05, 0.95])
        mapping = _build_ml_fallback_mapping(
            "user successfully logged in from trusted network", model
        )
        self.assertIsNone(mapping)

    def test_benign_prediction_keeps_no_mapping_in_full_pipeline(self) -> None:
        fake_model = _FakeModel("BENIGN", [0.05, 0.95])
        with patch(
            "src.desktop_services._resolve_fallback_model",
            return_value=fake_model,
        ):
            payload = analyze_soc_log(
                "user=alice successfully logged in from 10.0.0.8 and opened outlook.exe"
            )
        self.assertTrue(payload["ok"])
        self.assertEqual(payload.get("status"), "no_mapping")
        self.assertEqual(payload["summary"]["mapping_source"], "none")


class MlFallbackSoftBenignTests(unittest.TestCase):
    """When BENIGN wins only narrowly over the best attack class, the
    pipeline must surface that attack class as a low-confidence lead
    rather than silently returning "no mapping".  A confident BENIGN win
    still suppresses normally."""

    def test_confident_benign_still_suppressed(self) -> None:
        # BENIGN at 0.95, nearest attack T1059 at 0.02 (gap ~0.93) → suppress.
        model = _FakeModel(
            "BENIGN",
            [0.02, 0.01, 0.02, 0.95],
            classes=["T1059", "T1003", "T1204", "BENIGN"],
        )
        mapping = _build_ml_fallback_mapping(
            "user logged in from trusted workstation", model
        )
        self.assertIsNone(mapping)

    def test_narrow_benign_lead_surfaces_best_attack_as_low_confidence(self) -> None:
        # BENIGN narrowly above T1059 (gap 0.04 < soft margin 0.20) → the
        # pipeline must return T1059 with an explicit "low confidence"
        # rationale so the analyst still sees the lead.
        model = _FakeModel(
            "BENIGN",
            [0.18, 0.05, 0.03, 0.22],
            classes=["T1059", "T1003", "T1204", "BENIGN"],
        )
        mapping = _build_ml_fallback_mapping("short prose attack description", model)
        self.assertIsNotNone(mapping)
        assert mapping is not None
        self.assertEqual(mapping.technique_id, "T1059")
        self.assertIn("uncertain", mapping.rationale.lower())
        self.assertIn("benign_vs_attack_tied", mapping.evidence_refs)

    def test_narrow_benign_with_no_attack_classes_still_suppressed(self) -> None:
        # BENIGN narrowly wins but every other class is also BENIGN
        # (degenerate model) → suppress rather than fabricate a lead.
        model = _FakeModel("BENIGN", [0.5, 0.5], classes=["BENIGN", "BENIGN"])
        mapping = _build_ml_fallback_mapping("anything", model)
        self.assertIsNone(mapping)


class TimestampScrubbingTests(unittest.TestCase):
    """build_feature_text must normalise timestamps away so char n-grams
    never learn date-prefix shapes as class evidence."""

    def test_iso_timestamp_replaced_by_placeholder(self) -> None:
        result = build_feature_text(
            "2024-03-01T09:00:00Z WORKSTATION1 EventID=4688 process=cmd.exe"
        )
        self.assertNotIn("2024-03-01", result)
        self.assertNotIn("09:00:00", result)
        self.assertIn("ts_token", result.lower())

    def test_syslog_timestamp_replaced(self) -> None:
        result = build_feature_text("Feb 13 10:00:00 host42 pkexec started")
        self.assertNotIn("10:00:00", result)
        self.assertNotIn("Feb 13", result)
        self.assertIn("ts_token", result.lower())

    def test_log_without_timestamp_is_unchanged_aside_from_lowercase(self) -> None:
        # "powershell launched by explorer" carries no timestamp; the
        # feature text must preserve its content (case-insensitively) so
        # short prose logs remain classifiable.
        result = build_feature_text("powershell launched by explorer")
        self.assertIn("powershell", result)
        self.assertIn("launched by explorer", result)


class FeatureTextBuilderTests(unittest.TestCase):
    """build_feature_text must be deterministic and extract expected tokens."""

    def test_deterministic_on_repeated_calls(self) -> None:
        raw = "EventID=4625 user=alice process=powershell.exe src=10.0.0.1"
        self.assertEqual(build_feature_text(raw), build_feature_text(raw))

    def test_evtid_token_extracted(self) -> None:
        result = build_feature_text("EventID=4688 process=cmd.exe")
        self.assertIn("EVTID_4688", result)

    def test_proc_token_extracted(self) -> None:
        result = build_feature_text("new process: mimikatz.exe launched")
        self.assertIn("PROC_mimikatz.exe", result)

    def test_powershell_without_exe_suffix_extracted(self) -> None:
        result = build_feature_text("powershell -enc QUJDRA==")
        self.assertIn("PROC_powershell", result)

    def test_has_ip_token_when_ip_present(self) -> None:
        result = build_feature_text("src=192.168.1.100 attempt failed")
        self.assertIn("HAS_IP", result)

    def test_no_has_ip_token_when_no_ip(self) -> None:
        result = build_feature_text("just some text without any ip address here")
        self.assertNotIn("HAS_IP", result)

    def test_has_user_token_when_user_present(self) -> None:
        result = build_feature_text("user=CORP\\jsmith failed logon")
        self.assertIn("HAS_USER", result)

    def test_raw_text_always_included_lowercased(self) -> None:
        result = build_feature_text("MIMIKATZ SEKURLSA")
        self.assertIn("mimikatz sekurlsa", result)

    def test_empty_string_does_not_raise(self) -> None:
        result = build_feature_text("")
        self.assertIsInstance(result, str)


class MlFallbackBannerTests(unittest.TestCase):
    def test_banner_labels_ml_fallback_distinctly_from_rule_mapping(self) -> None:
        ml_payload = {
            "status": "mapped",
            "summary": {
                "technique_id": "T1071",
                "technique_name": "Application Layer Protocol",
                "evidence_strength": "weak",
                "mapping_source": "ml_fallback",
            }
        }
        rule_payload = {
            "status": "mapped",
            "summary": {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "evidence_strength": "strong",
                "mapping_source": "rule",
            }
        }
        ml_text, _, ml_tone = _soc_banner(ml_payload)
        rule_text, _, rule_tone = _soc_banner(rule_payload)

        self.assertIn("ML fallback", ml_text)
        self.assertIn("verify", ml_text.lower())
        self.assertIn("weak", ml_text)
        self.assertNotIn("%", ml_text)
        self.assertEqual(ml_tone, "info")

        self.assertIn("Rule-based", rule_text)
        self.assertIn("strong", rule_text)
        self.assertNotIn("%", rule_text)
        self.assertEqual(rule_tone, "success")


if __name__ == "__main__":
    unittest.main()
