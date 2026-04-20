from __future__ import annotations

import pickle
import re
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Feature-text builder (shared by training pipeline and inference path).
# ---------------------------------------------------------------------------
# Both train_model.py and the inference call in pipeline.py must call this
# function so that the text representation is identical at training and
# prediction time.  The function is intentionally narrow: it only extracts
# tokens that are deterministically recoverable from the raw log string
# itself, avoiding any training/inference distribution mismatch.

_EVTID_RE = re.compile(r"(?i)\bevent(?:_?id)?\s*(?:=|:)\s*(\d{3,5})\b")
_PROC_RE = re.compile(r"\b([a-zA-Z0-9_.-]+\.exe)\b", re.IGNORECASE)
_PORT_RE = re.compile(r"(?i)\b(?:dstport|dst_port|dest_port|port)\s*(?:=|:)\s*(\d{1,5})\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?i)\buser(?:name)?\s*(?:=|:)\s*\S+")
_DOMAIN_KW_RE = re.compile(r"(?i)\b(?:domain|fqdn|qname)\s*(?:=|:)\s*\S+")
_CMDLINE_RE = re.compile(r"(?i)\b(?:cmdline|command_line|cmd)\s*(?:=|:)\s*(.{4,120})")

# ---------------------------------------------------------------------------
# Timestamp scrubbing.
# ---------------------------------------------------------------------------
# Every Windows/Syslog example in the training corpus starts with a full
# timestamp (e.g. ``2024-03-01T09:00:00Z``, ``Feb 13 10:00:00``).  Raw
# char-n-gram TF-IDF then learns the *date prefix itself* as a class
# signal, because the shape of the timestamp correlates strongly with the
# log family in the training set.  That is a corpus artefact, not
# evidence — inference logs from a different source (or short prose logs
# with no timestamp at all) get misclassified because the leading
# characters don't match what the model saw during training.
#
# To eliminate that artefact we replace any recognisable timestamp with a
# single placeholder token (``TS_TOKEN``) in both the training feature
# text *and* the inference feature text.  The classifier loses nothing
# useful — the date itself is not intelligence — and stops keying on
# fragments like ``01T``, ``02-0``, ``10t18`` in the rationale tokens.

_TIMESTAMP_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Full ISO-8601 / RFC 3339: 2024-03-01T09:00:00(.123)?(Z|+01:00)?
    re.compile(
        r"\b\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
        r"(?:Z|[+-]\d{2}:?\d{2})?\b"
    ),
    # Syslog-style: "Feb 13 10:00:00" / "Mar  1 09:05:17"
    re.compile(
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+"
        r"\d{2}:\d{2}:\d{2}\b",
        re.IGNORECASE,
    ),
    # Date alone: 2024-03-01 / 2024/03/01
    re.compile(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b"),
    # Clock alone: 09:00:00 or 09:00
    re.compile(r"\b\d{2}:\d{2}(?::\d{2})?\b"),
    # Epoch-ish 10-digit numbers that look like unix timestamps
    re.compile(r"\b1[5-7]\d{8}\b"),
)

_TIMESTAMP_PLACEHOLDER = " TS_TOKEN "


def _scrub_timestamps(text: str) -> str:
    """Replace date/time stamps with a neutral placeholder.

    Called before feature extraction on both the training and inference
    paths so the model never learns the shape of a specific source's
    timestamp prefix as class evidence.
    """
    scrubbed = text
    for pattern in _TIMESTAMP_PATTERNS:
        scrubbed = pattern.sub(_TIMESTAMP_PLACEHOLDER, scrubbed)
    # Collapse runs of whitespace that the substitution may have produced
    # so downstream tokenisers see clean input.
    return re.sub(r"\s+", " ", scrubbed).strip()


def build_feature_text(raw_log: str) -> str:
    """Return an enriched text representation suitable for TF-IDF.

    The raw log text is lower-cased and combined with a small set of
    structured-token prefixes (``EVTID_``, ``PROC_``, ``PORT_``,
    ``HAS_IP``, ``HAS_USER``, ``HAS_DOMAIN``) extracted via simple regex.
    Raw timestamps are replaced by ``TS_TOKEN`` (see
    :func:`_scrub_timestamps`) so the classifier keys on log *content*
    rather than the shape of a particular source's date prefix.
    """
    scrubbed = _scrub_timestamps(raw_log)

    tokens: list[str] = [scrubbed.lower()]

    evtid_match = _EVTID_RE.search(scrubbed)
    if evtid_match:
        tokens.append(f"EVTID_{evtid_match.group(1)}")

    seen_procs: set[str] = set()
    for proc_match in _PROC_RE.finditer(scrubbed):
        proc = proc_match.group(1).lower()
        if proc not in seen_procs:
            seen_procs.add(proc)
            tokens.append(f"PROC_{proc}")
    if re.search(r"(?i)\bpowershell\b", scrubbed) and "powershell.exe" not in seen_procs:
        tokens.append("PROC_powershell")

    port_match = _PORT_RE.search(scrubbed)
    if port_match:
        tokens.append(f"PORT_{port_match.group(1)}")

    if _IP_RE.search(scrubbed):
        tokens.append("HAS_IP")

    if _USER_RE.search(scrubbed):
        tokens.append("HAS_USER")

    if _DOMAIN_KW_RE.search(scrubbed):
        tokens.append("HAS_DOMAIN")

    cmdline_match = _CMDLINE_RE.search(scrubbed)
    if cmdline_match:
        tokens.append(cmdline_match.group(1).lower())

    return " ".join(tokens)


# ---------------------------------------------------------------------------
# Prediction helpers.
# ---------------------------------------------------------------------------


def predict_attack(text: str, model: Any) -> dict[str, Any]:
    """Predict ATT&CK technique from raw log text.

    Returns the top-class technique_id, its probability (confidence), and
    the probability margin between the top-1 and top-2 classes.  The margin
    is used by the pipeline to gate uncertain predictions where two classes
    are nearly tied.

    When the loaded model is an ``AttackFallbackModel`` (the new composite
    artifact) the result additionally contains:

    * ``sub_technique_id`` / ``sub_technique_confidence`` — the refined
      sub-technique (e.g. ``T1059.001``) when the sub-head is confident,
      otherwise ``None``.
    * ``rationale_tokens`` — top TF-IDF tokens associated with the
      predicted parent class, suitable for surfacing in the UI.

    Older classifier artifacts continue to work; the extra keys are simply
    absent.  Callers should use ``.get(...)`` to read them.
    """
    feature_text = build_feature_text(text)
    predicted_label = str(model.predict([feature_text])[0])
    probabilities = model.predict_proba([feature_text])[0]

    class_names = [str(c) for c in getattr(model, "classes_", [])]
    # ``np.argsort`` is not ideal as a dependency here — use the builtin
    # ``enumerate`` + ``sorted`` path so this module keeps no compulsory
    # NumPy dependency at import time.
    ranked = sorted(
        (
            (class_names[i] if i < len(class_names) else "", float(prob))
            for i, prob in enumerate(probabilities)
        ),
        key=lambda pair: pair[1],
        reverse=True,
    )
    top1 = ranked[0][1] if ranked else 0.0
    top2 = ranked[1][1] if len(ranked) > 1 else 0.0
    margin = top1 - top2

    result: dict[str, Any] = {
        "technique_id": predicted_label,
        "confidence": top1,
        "margin": margin,
        # Full ranked list so the pipeline can inspect runner-up classes
        # (e.g. fall back to the top attack class when BENIGN wins by a
        # thin margin).
        "ranked_classes": ranked,
    }

    refine = getattr(model, "refine_with_subtechnique", None)
    if callable(refine):
        refined = refine(feature_text, predicted_label)
        if refined is not None:
            sub_label, sub_confidence = refined
            result["sub_technique_id"] = sub_label
            result["sub_technique_confidence"] = float(sub_confidence)

    top_tokens = getattr(model, "top_feature_tokens", None)
    if callable(top_tokens):
        tokens = top_tokens(predicted_label)
        if tokens:
            result["rationale_tokens"] = list(tokens)

    return result


def load_model(path: Path | str) -> Any:
    input_path = Path(path)
    with input_path.open("rb") as handle:
        model = pickle.load(handle)

    predict = getattr(model, "predict", None)
    predict_proba = getattr(model, "predict_proba", None)
    if not callable(predict) or not callable(predict_proba):
        raise ValueError("Loaded object is not a compatible classifier pipeline")

    return model
