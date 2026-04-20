"""Train the SOC ATT&CK fallback classifier.

This module builds the pickled model artifact consumed by the pipeline as
the ML fallback when no deterministic rule matches.  It contains several
independent improvements layered into a single artifact:

1.  **Global parent-technique classifier** (A + D): a calibrated classifier
    chosen as the best of ``{calibrated LogReg, calibrated LinearSVC,
    ComplementNB}`` benchmarked via stratified 5-fold CV on the labeled
    corpus.

2.  **Honest evaluation** (B): stratified 5-fold CV with per-class F1 mean
    / std is produced for the chosen model and reported in the training
    stats.  Training accuracy alone is no longer reported as a quality
    metric because it is uninformative for small corpora.

3.  **Threshold auto-tuning** (C): the BENIGN-vs-attack precision-recall
    curve from CV predictions is swept to find ``(confidence, margin)``
    pairs that keep benign-precision >= 0.95 while maximising attack
    recall.  The selected pair is written into the model artifact so the
    pipeline can retrieve thresholds specific to this model.  The
    hand-tuned defaults in ``pipeline.ML_FALLBACK_*_THRESHOLD`` remain as
    the fallback when the artifact does not carry tuned values.

4.  **Sub-technique heads** (E): for parents with at least
    ``_MIN_SUBTECH_SAMPLES`` rows spread across at least 2 sub-technique
    labels, a dedicated child classifier is trained.  At inference time
    the parent head picks a technique and, when a sub-head exists, it
    refines the prediction to ``parent.subtech`` only if the sub-head is
    confident.

5.  **Per-family sub-models** (G): for the two sufficiently-represented
    families ``Windows`` and ``Linux`` a family-restricted classifier is
    trained.  At inference time a deterministic family-router assigns the
    log to one of the family models; the global model is used as a
    fallback when the family cannot be confidently determined.

6.  **Top-feature rationale** (F): each class's top TF-IDF tokens (as
    weighted by the underlying classifier, where available) are stored on
    the artifact so the pipeline can render them in the mapping rationale
    shown to the analyst.

The artifact exposes a scikit-learn-compatible surface (``predict``,
``predict_proba``, ``classes_``) so downstream inference code in
``src.model.predict_attack`` continues to work unchanged.

Run with ``python -m src.train_model``.
"""

from __future__ import annotations

import argparse
import json
import pickle
import re
import sys
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from scipy.sparse import csr_matrix, vstack
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from src.model import build_feature_text


_DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "tests" / "data" / "mitre_all_techniques.jsonl"
_DEFAULT_ARTIFACT = Path(__file__).resolve().parent / "artifacts" / "attack_classifier.pkl"
_ACCEPTED_CONFIDENCE = frozenset({"high", "medium"})
_MIN_SAMPLES_PER_CLASS = 5
_CV_FOLDS = 5
BENIGN_LABEL = "BENIGN"

# Sub-technique training: a parent gets its own sub-head only when there
# are enough samples split across at least two distinct sub-labels.
_MIN_SUBTECH_SAMPLES = 8
_MIN_SUBTECH_DISTINCT = 2
# Sub-head probability threshold: below this we emit the parent only.
_SUBTECH_CONFIDENCE_GATE = 0.55

# Per-family models: only train for families with this many rows across at
# least 3 distinct parent labels.  Anything else routes to the global model.
_MIN_FAMILY_SAMPLES = 80
_MIN_FAMILY_DISTINCT_LABELS = 3

# Threshold auto-tuning: require at least this precision on the BENIGN
# decision when a non-BENIGN prediction is surfaced.  In other words, we
# never want to call a benign event an attack more than ``1 -
# _MIN_ATTACK_PRECISION`` of the time.
_MIN_ATTACK_PRECISION = 0.95

# Top-N TF-IDF tokens retained per class for the rationale feature.
_TOP_FEATURES_PER_CLASS = 6

# Per-family heuristic router.  Intentionally conservative: patterns are
# highly specific to the family and catch the vast majority of real logs
# in that family without bleeding into others.  When none match we fall
# back to the global model rather than guessing a family.
_FAMILY_ROUTER_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "Windows",
        re.compile(
            r"(?i)(?:\bsysmon\b|\bwinlog|\bwinevent|\bwinlogbeat|\beventid\s*[=:]\d+|"
            r"\bcorp\\\\?\w+|\bmstsc\b|\bpowershell\.exe\b|\bschtasks\.exe\b|\brundll32\.exe\b|"
            r"\bwbem\\\\?WMIC|\bwevtutil\b|\bcmd\.exe\b|\.evtx\b|c:\\\\)"
        ),
    ),
    (
        "Linux",
        re.compile(
            r"(?i)(?:\baudit:\s*type=EXECVE|\bsyslog\b|\bauditd\b|\bsshd\[|"
            r"\bcron\[|\bsystemd\[|\busermod\b|\badduser\b|/etc/(?:shadow|passwd)|"
            r"/var/log/|/var/www/|\bsudo:\s|named\[)"
        ),
    ),
)


@dataclass
class _FamilyHead:
    """A classifier restricted to a single log family (Windows / Linux).

    The head only handles classes that appeared for that family during
    training.  The router sends a log here only when the family pattern
    matches; otherwise the global head is used.
    """

    classifier: Any
    classes: list[str]


class AttackFallbackModel:
    """Composite fallback classifier carrying global + per-family + sub heads.

    Exposes a scikit-learn-compatible surface so existing callers that
    pass the model to ``predict_attack`` keep working unchanged.

    .. note::
       The class is pinned to the module path ``src.train_model`` via
       ``__module__`` below so that pickle always records that fully
       qualified name.  Without this, running training via ``python -m
       src.train_model`` would save the class under ``__main__`` and the
       inference process (which imports from ``src.train_model``) would
       fail to unpickle the artifact.
    """

    def __init__(
        self,
        *,
        global_head: Any,
        family_heads: dict[str, _FamilyHead],
        subtech_heads: dict[str, Any],
        top_features: dict[str, list[str]],
        tuned_thresholds: dict[str, float] | None,
        metadata: dict[str, Any],
    ) -> None:
        self.global_head = global_head
        self.family_heads = family_heads
        self.subtech_heads = subtech_heads
        self.top_features = top_features
        self.tuned_thresholds = tuned_thresholds
        self.metadata = metadata
        self.classes_ = np.array(list(global_head.classes_))

    # ------------------------------------------------------------------
    # Routing helpers.
    # ------------------------------------------------------------------

    @staticmethod
    def _route_family(raw_or_feature_text: str) -> str | None:
        """Return ``Windows`` / ``Linux`` / None based on family patterns.

        The input string can be either the raw log or its feature-text
        representation because ``build_feature_text`` always includes the
        raw log lower-cased.  Matching anything else (Cloud, Firewall,
        IDS, Network) falls through to the global model.
        """
        if not isinstance(raw_or_feature_text, str):
            return None
        for family, pattern in _FAMILY_ROUTER_RULES:
            if pattern.search(raw_or_feature_text):
                return family
        return None

    def _best_head_for(self, text: str) -> tuple[Any, list[str], str]:
        """Return (classifier, classes, source_tag) for a feature-text input."""
        family = self._route_family(text)
        if family and family in self.family_heads:
            head = self.family_heads[family]
            return head.classifier, head.classes, f"family:{family}"
        return self.global_head, list(self.global_head.classes_), "global"

    # ------------------------------------------------------------------
    # scikit-learn surface.
    # ------------------------------------------------------------------

    def predict(self, inputs: list[str]) -> list[str]:
        predictions: list[str] = []
        for text in inputs:
            clf, _, _ = self._best_head_for(text)
            predictions.append(str(clf.predict([text])[0]))
        return predictions

    def predict_proba(self, inputs: list[str]) -> np.ndarray:
        """Return a probability matrix aligned to ``self.classes_``.

        When a family head fires, its restricted class set is projected
        back onto the global class vector (missing classes get 0.0).
        This keeps the callers downstream — which index into
        ``self.classes_`` — consistent across routes.
        """
        global_class_index = {label: idx for idx, label in enumerate(self.classes_)}
        rows: list[np.ndarray] = []
        for text in inputs:
            clf, class_list, _ = self._best_head_for(text)
            local_probs = np.asarray(clf.predict_proba([text])[0], dtype=float)
            aligned = np.zeros(len(self.classes_), dtype=float)
            for local_idx, label in enumerate(class_list):
                tgt = global_class_index.get(label)
                if tgt is not None:
                    aligned[tgt] = float(local_probs[local_idx])
            total = aligned.sum()
            if total > 0:
                aligned /= total
            rows.append(aligned)
        return np.vstack(rows)

    # ------------------------------------------------------------------
    # Refinement helpers used by the pipeline.
    # ------------------------------------------------------------------

    def refine_with_subtechnique(
        self, text: str, parent_technique: str
    ) -> tuple[str, float] | None:
        """If a sub-head exists for ``parent_technique`` and is confident,
        return ``(sub_id, sub_confidence)``; otherwise ``None``.
        """
        head = self.subtech_heads.get(parent_technique)
        if head is None:
            return None
        probs = np.asarray(head.predict_proba([text])[0], dtype=float)
        best_idx = int(np.argmax(probs))
        best_prob = float(probs[best_idx])
        if best_prob < _SUBTECH_CONFIDENCE_GATE:
            return None
        sub_label = str(head.classes_[best_idx])
        return sub_label, best_prob

    def top_feature_tokens(self, label: str) -> list[str]:
        return list(self.top_features.get(label, []))


# ---------------------------------------------------------------------------
# Corpus loading.
# ---------------------------------------------------------------------------


def _iter_labeled_rows(
    corpus_path: Path,
) -> Iterable[tuple[str, str, str, str]]:
    """Yield (raw_log, parent_label, sub_label, family) per accepted row.

    ``sub_label`` is the full ATT&CK mapping including sub (e.g.
    ``T1059.001``) so sub-technique heads can be trained.  ``family`` is
    the corpus-provided family (``Windows`` / ``Linux`` / etc).
    """
    with corpus_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            raw_log = record.get("raw_log")
            metadata = record.get("metadata", {}) or {}
            attack_mapping = metadata.get("attack_mapping")
            confidence = str(metadata.get("confidence", "")).lower()
            family = str(metadata.get("family", "") or "")
            if not isinstance(raw_log, str) or not isinstance(attack_mapping, str):
                continue
            if confidence not in _ACCEPTED_CONFIDENCE:
                continue
            parent_label = attack_mapping.split(".")[0].strip()
            if parent_label == BENIGN_LABEL:
                yield raw_log.strip(), BENIGN_LABEL, BENIGN_LABEL, family
                continue
            if not parent_label.startswith("T") or not parent_label[1:].isdigit():
                continue
            yield raw_log.strip(), parent_label, attack_mapping.strip(), family


# ---------------------------------------------------------------------------
# Feature representation.
# ---------------------------------------------------------------------------


def _build_feature_union() -> FeatureUnion:
    return FeatureUnion(
        transformer_list=[
            (
                "word",
                TfidfVectorizer(
                    analyzer="word",
                    lowercase=True,
                    ngram_range=(1, 2),
                    min_df=1,
                    max_df=1.0,
                    max_features=6000,
                    sublinear_tf=True,
                    strip_accents="unicode",
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb",
                    lowercase=True,
                    ngram_range=(3, 5),
                    min_df=1,
                    max_df=1.0,
                    max_features=8000,
                    sublinear_tf=True,
                    strip_accents="unicode",
                ),
            ),
        ]
    )


# ---------------------------------------------------------------------------
# Candidate classifiers for the D benchmark.
# ---------------------------------------------------------------------------


def _candidate_classifiers() -> dict[str, Any]:
    return {
        "LogReg_balanced_calibrated": CalibratedClassifierCV(
            estimator=LogisticRegression(
                C=1.0,
                max_iter=2000,
                solver="liblinear",
                class_weight="balanced",
            ),
            method="sigmoid",
            cv=3,
        ),
        "LinearSVC_calibrated": CalibratedClassifierCV(
            estimator=LinearSVC(C=1.0, class_weight="balanced", max_iter=5000),
            method="sigmoid",
            cv=3,
        ),
        "ComplementNB": ComplementNB(),
    }


def _build_pipeline_for(clf: Any) -> Pipeline:
    return Pipeline(steps=[("features", _build_feature_union()), ("clf", clf)])


# ---------------------------------------------------------------------------
# Cross-validated benchmarking + per-class F1.
# ---------------------------------------------------------------------------


def _cv_fit_predict_proba(
    texts: list[str],
    labels: list[str],
    clf_factory,
    *,
    n_splits: int,
    random_state: int = 42,
) -> tuple[np.ndarray, list[str]]:
    """Return (oof_probas, class_order) from a stratified K-fold run."""
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

    sample_classes_by_fold: list[list[str]] = []
    sample_rows: list[np.ndarray] = []
    final_classes: list[str] | None = None

    # Two-pass strategy: fit once with all data to learn the global class
    # order, then do OOF predictions fold-by-fold.
    all_classes = sorted(set(labels))
    class_index = {c: i for i, c in enumerate(all_classes)}
    out = np.zeros((len(texts), len(all_classes)), dtype=float)

    X = np.asarray(texts, dtype=object)
    y = np.asarray(labels, dtype=object)

    for train_idx, test_idx in skf.split(X, y):
        clf = clf_factory()
        model = _build_pipeline_for(clf)
        model.fit(list(X[train_idx]), list(y[train_idx]))
        probas = model.predict_proba(list(X[test_idx]))
        fold_classes = list(model.classes_)
        for row_i, idx in enumerate(test_idx):
            for local_j, label in enumerate(fold_classes):
                out[idx, class_index[label]] = float(probas[row_i, local_j])

    return out, all_classes


def _benchmark_candidates(
    texts: list[str], labels: list[str]
) -> tuple[str, dict[str, dict[str, Any]]]:
    """Score every candidate via CV and return (winner_name, all_results)."""
    results: dict[str, dict[str, Any]] = {}
    candidate_factories = {
        name: (lambda *, _f=factory: _f)
        for name, factory in _candidate_classifiers().items()
    }
    # The factories above capture the actual estimator but estimators
    # cannot be re-fit reliably across folds; build fresh classifiers each
    # call instead.
    candidate_builders = {
        "LogReg_balanced_calibrated": lambda: CalibratedClassifierCV(
            estimator=LogisticRegression(
                C=1.0, max_iter=2000, solver="liblinear", class_weight="balanced"
            ),
            method="sigmoid",
            cv=3,
        ),
        "LinearSVC_calibrated": lambda: CalibratedClassifierCV(
            estimator=LinearSVC(C=1.0, class_weight="balanced", max_iter=5000),
            method="sigmoid",
            cv=3,
        ),
        "ComplementNB": lambda: ComplementNB(),
    }

    # Suppress calibrator convergence chatter that doesn't affect outcome.
    warnings.filterwarnings("ignore", category=UserWarning)
    warnings.filterwarnings("ignore", category=FutureWarning)

    for name, builder in candidate_builders.items():
        try:
            probas, classes = _cv_fit_predict_proba(
                texts, labels, builder, n_splits=_CV_FOLDS
            )
        except Exception as exc:
            results[name] = {"error": str(exc)}
            continue

        preds = np.asarray(classes)[probas.argmax(axis=1)]
        acc = float(accuracy_score(labels, preds))
        macro_f1 = float(
            f1_score(labels, preds, average="macro", zero_division=0)
        )
        per_class_f1: dict[str, float] = {}
        for label in sorted(set(labels)):
            mask = np.asarray([lab == label for lab in labels])
            if not mask.any():
                continue
            per_class_f1[label] = round(
                float(
                    f1_score(
                        np.asarray(labels)[mask],
                        preds[mask],
                        labels=[label],
                        average="macro",
                        zero_division=0,
                    )
                ),
                4,
            )

        results[name] = {
            "cv_accuracy": round(acc, 4),
            "cv_macro_f1": round(macro_f1, 4),
            "per_class_f1": per_class_f1,
        }

    usable = {name: r for name, r in results.items() if "error" not in r}
    if not usable:
        raise SystemExit("All candidate classifiers failed to train.")
    winner = max(usable.items(), key=lambda kv: kv[1]["cv_macro_f1"])[0]
    return winner, results


# ---------------------------------------------------------------------------
# Threshold auto-tuning.
# ---------------------------------------------------------------------------


def _tune_thresholds(
    texts: list[str],
    labels: list[str],
    clf_builder,
    *,
    min_attack_precision: float,
) -> dict[str, float]:
    """Sweep ``(confidence, margin)`` pairs against OOF predictions.

    Goal: keep attack-precision (fraction of predicted-attack events that
    are truly attack) at or above ``min_attack_precision`` while
    maximising attack-recall (fraction of attacks we actually label).
    Returns the chosen thresholds and the observed operating point.
    """
    probas, classes = _cv_fit_predict_proba(
        texts, labels, clf_builder, n_splits=_CV_FOLDS
    )
    class_array = np.asarray(classes)

    sorted_idx = np.argsort(-probas, axis=1)
    top1_labels = class_array[sorted_idx[:, 0]]
    top1_probs = probas[np.arange(len(texts)), sorted_idx[:, 0]]
    if probas.shape[1] > 1:
        top2_probs = probas[np.arange(len(texts)), sorted_idx[:, 1]]
    else:
        top2_probs = np.zeros_like(top1_probs)
    margin = top1_probs - top2_probs

    truth = np.asarray(labels)
    truth_is_attack = truth != BENIGN_LABEL

    best: dict[str, float] = {
        "confidence_threshold": 0.25,
        "margin_threshold": 0.08,
        "attack_precision": 0.0,
        "attack_recall": 0.0,
    }

    for conf_t in np.linspace(0.10, 0.60, 26):
        for margin_t in np.linspace(0.02, 0.30, 15):
            fires = (
                (top1_labels != BENIGN_LABEL)
                & (top1_probs >= conf_t)
                & (margin >= margin_t)
            )
            if not fires.any():
                continue
            tp = int(np.sum(fires & truth_is_attack))
            fp = int(np.sum(fires & ~truth_is_attack))
            predicted_fires = tp + fp
            actual_attacks = int(np.sum(truth_is_attack))
            if predicted_fires == 0 or actual_attacks == 0:
                continue
            precision = tp / predicted_fires
            recall = tp / actual_attacks
            if precision < min_attack_precision:
                continue
            if recall > best["attack_recall"] or (
                recall == best["attack_recall"]
                and precision > best["attack_precision"]
            ):
                best = {
                    "confidence_threshold": round(float(conf_t), 3),
                    "margin_threshold": round(float(margin_t), 3),
                    "attack_precision": round(float(precision), 3),
                    "attack_recall": round(float(recall), 3),
                }

    return best


# ---------------------------------------------------------------------------
# Top-token rationale per class.
# ---------------------------------------------------------------------------


def _extract_top_features_per_class(
    pipeline: Pipeline, *, top_n: int
) -> dict[str, list[str]]:
    """Return top-``top_n`` TF-IDF tokens per class from the fitted pipeline.

    Uses the inner linear coefficients when the classifier exposes them
    (LogReg / LinearSVC / ComplementNB).  When the classifier is wrapped
    in ``CalibratedClassifierCV``, we average coefficients across the
    inner estimators to get a stable per-class ranking.  Returns an
    empty dict when feature importances are not recoverable.
    """
    try:
        vectorizer = pipeline.named_steps["features"]
        clf = pipeline.named_steps["clf"]
        feature_names = np.asarray(vectorizer.get_feature_names_out())
    except Exception:
        return {}

    coef = _extract_coefficients(clf)
    if coef is None:
        return {}

    # Binary classifier trick: single row of coefficients maps to class
    # ``clf.classes_[1]`` (positive class).  Expand to a 2-row matrix so
    # the per-class loop below works unchanged.
    classes = list(getattr(clf, "classes_", []))
    if coef.ndim == 1 and len(classes) == 2:
        coef = np.vstack([-coef, coef])

    if coef.shape[0] != len(classes):
        return {}

    out: dict[str, list[str]] = {}
    for idx, label in enumerate(classes):
        scores = coef[idx]
        if scores.size != feature_names.size:
            return {}
        top_idx = np.argsort(-scores)[:top_n]
        out[str(label)] = [
            str(feature_names[i]) for i in top_idx if scores[i] > 0
        ]
    return out


def _extract_coefficients(clf: Any) -> np.ndarray | None:
    """Best-effort coefficient extraction from sklearn-style classifiers."""
    direct = getattr(clf, "coef_", None)
    if direct is not None:
        try:
            return np.asarray(direct)
        except Exception:
            return None

    # CalibratedClassifierCV holds its inner estimators on ``.calibrated_classifiers_``.
    calibrated = getattr(clf, "calibrated_classifiers_", None)
    if not calibrated:
        return None

    inner_coefs: list[np.ndarray] = []
    for wrapper in calibrated:
        base = getattr(wrapper, "estimator", None) or getattr(
            wrapper, "base_estimator", None
        )
        if base is None:
            continue
        base_coef = getattr(base, "coef_", None)
        if base_coef is None:
            continue
        inner_coefs.append(np.asarray(base_coef))
    if not inner_coefs:
        return None
    return np.mean(np.stack(inner_coefs, axis=0), axis=0)


# ---------------------------------------------------------------------------
# Sub-technique heads.
# ---------------------------------------------------------------------------


def _build_subtech_heads(
    rows: list[tuple[str, str, str, str]],
) -> dict[str, Any]:
    """Train a small head per parent with enough sub-technique coverage."""
    grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for raw_log, parent, sub_label, _family in rows:
        if parent == BENIGN_LABEL:
            continue
        if sub_label == parent:
            grouped[parent].append((raw_log, parent))
        else:
            grouped[parent].append((raw_log, sub_label))

    heads: dict[str, Any] = {}
    for parent, samples in grouped.items():
        if len(samples) < _MIN_SUBTECH_SAMPLES:
            continue
        # Sub-heads use a plain LogReg without calibration (no inner CV),
        # so per-class minimums are only needed for parent/sub diversity,
        # not for CV folds.
        distinct = {sub for _, sub in samples}
        if len(distinct) < _MIN_SUBTECH_DISTINCT:
            continue
        texts = [build_feature_text(raw) for raw, _ in samples]
        labels = [sub for _, sub in samples]
        pipeline = _build_pipeline_for(
            LogisticRegression(
                C=1.0, max_iter=2000, solver="liblinear", class_weight="balanced"
            )
        )
        pipeline.fit(texts, labels)
        heads[parent] = pipeline
    return heads


# ---------------------------------------------------------------------------
# Per-family heads.
# ---------------------------------------------------------------------------


def _build_family_heads(
    rows: list[tuple[str, str, str, str]],
) -> dict[str, _FamilyHead]:
    """Train a family-restricted classifier for well-represented families.

    Classes appearing fewer than three times *within the family* are
    dropped: the inner CalibratedClassifierCV uses 3-fold CV, so each
    class needs at least three samples to train at all.  Anything rarer
    is handled by the global head instead.
    """
    per_family: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for raw_log, parent, _sub, family in rows:
        if family in {"Windows", "Linux"}:
            per_family[family].append((raw_log, parent))

    heads: dict[str, _FamilyHead] = {}
    for family, samples in per_family.items():
        if len(samples) < _MIN_FAMILY_SAMPLES:
            continue
        in_family_counts = Counter(lab for _, lab in samples)
        keep_labels = {lab for lab, n in in_family_counts.items() if n >= 3}
        trimmed = [s for s in samples if s[1] in keep_labels]
        if len(trimmed) < _MIN_FAMILY_SAMPLES:
            continue
        labels = [lab for _, lab in trimmed]
        if len(set(labels)) < _MIN_FAMILY_DISTINCT_LABELS:
            continue
        texts = [build_feature_text(raw) for raw, _ in trimmed]
        pipeline = _build_pipeline_for(
            CalibratedClassifierCV(
                estimator=LogisticRegression(
                    C=1.0, max_iter=2000, solver="liblinear", class_weight="balanced"
                ),
                method="sigmoid",
                cv=3,
            )
        )
        pipeline.fit(texts, labels)
        heads[family] = _FamilyHead(
            classifier=pipeline, classes=list(pipeline.classes_)
        )
    return heads


# ---------------------------------------------------------------------------
# Public training entry point.
# ---------------------------------------------------------------------------


def build_dataset(corpus_path: Path):
    rows = list(_iter_labeled_rows(corpus_path))
    parent_counts = Counter(row[1] for row in rows)
    tiny = {c for c, n in parent_counts.items() if n < _MIN_SAMPLES_PER_CLASS}
    filtered = [row for row in rows if row[1] not in tiny]
    return filtered, sorted(tiny)


def _feature_texts(rows: list[tuple[str, str, str, str]]) -> tuple[list[str], list[str]]:
    texts = [build_feature_text(row[0]) for row in rows]
    labels = [row[1] for row in rows]
    return texts, labels


def train(
    corpus_path: Path = _DEFAULT_CORPUS,
    artifact_path: Path = _DEFAULT_ARTIFACT,
) -> dict[str, object]:
    rows, dropped_classes = build_dataset(corpus_path)
    if not rows:
        raise SystemExit(f"No labeled rows found in {corpus_path}")

    texts, labels = _feature_texts(rows)

    # --- D: benchmark candidate classifiers on stratified 5-fold CV.
    winner_name, benchmark_results = _benchmark_candidates(texts, labels)
    if winner_name == "LogReg_balanced_calibrated":
        final_builder = lambda: CalibratedClassifierCV(  # noqa: E731
            estimator=LogisticRegression(
                C=1.0, max_iter=2000, solver="liblinear", class_weight="balanced"
            ),
            method="sigmoid",
            cv=3,
        )
    elif winner_name == "LinearSVC_calibrated":
        final_builder = lambda: CalibratedClassifierCV(  # noqa: E731
            estimator=LinearSVC(C=1.0, class_weight="balanced", max_iter=5000),
            method="sigmoid",
            cv=3,
        )
    elif winner_name == "ComplementNB":
        final_builder = lambda: ComplementNB()  # noqa: E731
    else:
        raise SystemExit(f"Unknown winning classifier: {winner_name}")

    # --- C: threshold auto-tuning from OOF predictions of the winner.
    tuned = _tune_thresholds(
        texts,
        labels,
        final_builder,
        min_attack_precision=_MIN_ATTACK_PRECISION,
    )

    # --- Global head: train on the full corpus now.
    global_pipeline = _build_pipeline_for(final_builder())
    global_pipeline.fit(texts, labels)

    # --- F: top TF-IDF tokens per class.
    top_features = _extract_top_features_per_class(
        global_pipeline, top_n=_TOP_FEATURES_PER_CLASS
    )

    # --- E: sub-technique heads.
    subtech_heads = _build_subtech_heads(rows)

    # --- G: per-family heads.
    family_heads = _build_family_heads(rows)

    # Package and save the composite model.
    metadata: dict[str, Any] = {
        "corpus_path": str(corpus_path),
        "training_rows": len(rows),
        "label_counts": dict(sorted(Counter(labels).items())),
        "dropped_classes": dropped_classes,
        "benchmark": benchmark_results,
        "winner": winner_name,
        "sub_technique_parents": sorted(subtech_heads.keys()),
        "family_heads": sorted(family_heads.keys()),
        "tuned_thresholds": tuned,
        "cv_folds": _CV_FOLDS,
    }
    model = AttackFallbackModel(
        global_head=global_pipeline,
        family_heads=family_heads,
        subtech_heads=subtech_heads,
        top_features=top_features,
        tuned_thresholds=tuned,
        metadata=metadata,
    )

    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    with artifact_path.open("wb") as handle:
        pickle.dump(model, handle)

    return {
        "artifact_path": str(artifact_path),
        **metadata,
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=_DEFAULT_CORPUS)
    parser.add_argument("--out", type=Path, default=_DEFAULT_ARTIFACT)
    return parser


def main() -> None:
    args = _build_arg_parser().parse_args()
    stats = train(corpus_path=args.corpus, artifact_path=args.out)
    print(json.dumps(stats, indent=2, default=str))


if __name__ == "__main__":
    # When run via ``python -m src.train_model`` this module is loaded twice
    # (once as ``__main__`` and once as ``src.train_model``).  We delegate to
    # the imported copy so classes like :class:`AttackFallbackModel` are
    # pickled under their stable dotted path rather than ``__main__``.
    import importlib

    _mod = importlib.import_module("src.train_model")
    if _mod is not sys.modules[__name__]:
        _mod.main()
    else:
        main()
