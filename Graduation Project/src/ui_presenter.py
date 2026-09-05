from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AnalysisState(str, Enum):
    MAPPED = "mapped"
    MAPPED_LOW_CONFIDENCE = "mapped_low_confidence"
    NO_MAPPING = "no_mapping"
    MALFORMED = "malformed"
    ERROR = "error"


@dataclass(frozen=True)
class StateCopy:
    label: str
    tone: str
    explanation: str
    next_action: str


_STATE_COPY: dict[AnalysisState, StateCopy] = {
    AnalysisState.MAPPED: StateCopy(
        label="Mapped",
        tone="success",
        explanation="The analyzer produced an ATT&CK mapping backed by strong or moderate evidence.",
        next_action="Review the mapping and recommended response plan, then triage per playbook.",
    ),
    AnalysisState.MAPPED_LOW_CONFIDENCE: StateCopy(
        label="Mapped (weak evidence)",
        tone="warning",
        explanation="An ATT&CK technique matched but the evidence is weak. Treat the result as preliminary.",
        next_action="Inspect the cited evidence and verify with a second data source before responding.",
    ),
    AnalysisState.NO_MAPPING: StateCopy(
        label="No reliable ATT&CK mapping",
        tone="info",
        explanation="The analyzer completed but no ATT&CK rule matched. This is the expected outcome for benign traffic or inputs the rule table cannot currently express.",
        next_action="Review the extracted entities, add correlated log lines, and re-run.",
    ),
    AnalysisState.MALFORMED: StateCopy(
        label="Malformed log",
        tone="warning",
        explanation="The analyzer could not extract meaningful structure from this input.",
        next_action="Confirm the log source format and re-submit with a representative sample.",
    ),
    AnalysisState.ERROR: StateCopy(
        label="Analysis error",
        tone="danger",
        explanation="The analyzer failed to complete. No findings should be trusted.",
        next_action="Inspect the raw log and the reported error message.",
    ),
}


def state_copy(state: AnalysisState) -> StateCopy:
    return _STATE_COPY[state]


@dataclass
class EntityView:
    type: str
    value: str
    evidence_ref: str | None = None
    start: int | None = None
    end: int | None = None
    source: str = "unknown"


@dataclass
class MappingView:
    technique_id: str | None = None
    technique_name: str | None = None
    evidence_strength: str | None = None
    source: str | None = None
    match_type: str = "none"
    rationale: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    secondary_techniques: list[str] = field(default_factory=list)


@dataclass
class AnalysisBreakdown:
    state: AnalysisState
    state_copy: StateCopy
    outcome_summary: str
    mapping: MappingView = field(default_factory=MappingView)
    entities: list[EntityView] = field(default_factory=list)
    weak_signals: list[str] = field(default_factory=list)
    error_message: str | None = None
    raw_log: str = ""
    normalized_event: dict[str, Any] = field(default_factory=dict)


def _result_block(payload: dict[str, Any]) -> dict[str, Any]:
    result = payload.get("result")
    if isinstance(result, dict) and result:
        return result
    partial = payload.get("partial_result")
    if isinstance(partial, dict):
        return partial
    return {}


def _classify_state(
    payload: dict[str, Any],
    *,
    mapping: MappingView,
    entity_count: int,
) -> AnalysisState:
    ok = bool(payload.get("ok"))
    status = str(payload.get("status") or "").strip().lower()
    reason = str(payload.get("reason") or "").strip().lower()
    error_message = str(payload.get("error") or "").strip()

    if ok and mapping.technique_id:
        if mapping.evidence_strength == "weak":
            return AnalysisState.MAPPED_LOW_CONFIDENCE
        return AnalysisState.MAPPED

    if ok and status == "no_mapping":
        if entity_count == 0:
            return AnalysisState.MALFORMED
        return AnalysisState.NO_MAPPING

    # A validation_error / internal_error reason means the pipeline had a
    # real correctness problem — treat it as an error, NOT as no-mapping,
    # so internal bugs never silently look like a benign unmapped result.
    if not ok and reason in {"validation_error", "internal_error"}:
        return AnalysisState.ERROR

    if not ok and error_message:
        return AnalysisState.ERROR

    if mapping.technique_id:
        return AnalysisState.MAPPED

    return AnalysisState.NO_MAPPING


def _weak_signals(
    *,
    state: AnalysisState,
    mapping: MappingView,
    entity_count: int,
) -> list[str]:
    concerns: list[str] = []
    if state == AnalysisState.MAPPED_LOW_CONFIDENCE:
        concerns.append("Weak-evidence mapping")
    if mapping.source == "ml_fallback":
        concerns.append("Mapping from ML fallback — verify manually")
    if state == AnalysisState.MALFORMED:
        concerns.append("No entities extracted from input")
    return concerns


def build_breakdown(payload: dict[str, Any], *, raw_log: str = "") -> AnalysisBreakdown:
    if not isinstance(payload, dict):
        payload = {}

    result = _result_block(payload)
    audit = result.get("audit") if isinstance(result.get("audit"), dict) else {}
    normalized = audit.get("normalized_event") if isinstance(audit.get("normalized_event"), dict) else {}
    entities_raw = result.get("entities") if isinstance(result.get("entities"), list) else []
    attack_raw = result.get("attack_mapping") if isinstance(result.get("attack_mapping"), list) else []

    entities = [
        EntityView(
            type=str(e.get("type", "")),
            value=str(e.get("value", "")),
            evidence_ref=e.get("evidence_ref"),
            start=e.get("start"),
            end=e.get("end"),
            source=str(e.get("source", "unknown")),
        )
        for e in entities_raw
        if isinstance(e, dict)
    ]

    mapping = MappingView()
    if attack_raw:
        first = attack_raw[0] if isinstance(attack_raw[0], dict) else {}
        mapping = MappingView(
            technique_id=first.get("technique_id"),
            technique_name=first.get("technique_name"),
            evidence_strength=str(first.get("evidence_strength")) if first.get("evidence_strength") else None,
            source=first.get("source") or audit.get("mapping_source"),
            match_type=str(first.get("match_type", "rule")),
            rationale=first.get("rationale"),
            evidence_refs=[str(e) for e in (first.get("evidence_refs") or [])],
            secondary_techniques=[
                str(m.get("technique_id", ""))
                for m in attack_raw[1:]
                if isinstance(m, dict) and m.get("technique_id")
            ],
        )

    state = _classify_state(payload, mapping=mapping, entity_count=len(entities))
    copy = state_copy(state)

    weak = _weak_signals(state=state, mapping=mapping, entity_count=len(entities))

    if state == AnalysisState.MAPPED:
        outcome_summary = f"Mapped to {mapping.technique_id} ({mapping.technique_name}) with {mapping.evidence_strength or 'unknown'} evidence." if mapping.technique_id else "Mapped."
    elif state == AnalysisState.MAPPED_LOW_CONFIDENCE:
        outcome_summary = f"Weak-evidence mapping to {mapping.technique_id}. Review before acting." if mapping.technique_id else "Weak-evidence mapping."
    elif state == AnalysisState.NO_MAPPING:
        outcome_summary = f"No reliable ATT&CK mapping. {len(entities)} entities extracted."
    elif state == AnalysisState.MALFORMED:
        outcome_summary = "Input was malformed — no entities or mapping produced."
    else:
        outcome_summary = str(payload.get("error") or "Analysis failed.")

    error_message: str | None = None
    if state == AnalysisState.ERROR:
        err = payload.get("error")
        if isinstance(err, str) and err.strip():
            error_message = err.strip()

    return AnalysisBreakdown(
        state=state,
        state_copy=copy,
        outcome_summary=outcome_summary,
        mapping=mapping,
        entities=entities,
        weak_signals=weak,
        error_message=error_message,
        raw_log=raw_log,
        normalized_event=dict(normalized),
    )


def format_raw_log(breakdown: AnalysisBreakdown) -> str:
    return breakdown.raw_log or ""


def format_normalized_fields(breakdown: AnalysisBreakdown) -> str:
    if not breakdown.normalized_event:
        return "(no normalized fields extracted)"
    lines = []
    for key in sorted(breakdown.normalized_event):
        value = breakdown.normalized_event[key]
        lines.append(f"{key}: {value}")
    return "\n".join(lines)


def format_mapping_summary(breakdown: AnalysisBreakdown) -> str:
    m = breakdown.mapping
    lines = [
        f"State: {breakdown.state_copy.label}",
    ]
    if m.technique_id:
        lines.append(
            f"ATT&CK: {m.technique_id} ({m.technique_name or 'unknown'}) "
            f"via {m.source or 'rule'}, evidence {m.evidence_strength or 'n/a'}"
        )
    else:
        lines.append("ATT&CK: none")
    if m.rationale:
        lines.append(f"Rationale: {m.rationale}")
    if m.evidence_refs:
        evidence = "; ".join(str(e) for e in m.evidence_refs[:5])
        lines.append(f"Evidence: {evidence}")
    if breakdown.weak_signals:
        lines.append("Concerns: " + "; ".join(breakdown.weak_signals))
    return "\n".join(lines)


__all__ = [
    "AnalysisBreakdown",
    "AnalysisState",
    "EntityView",
    "MappingView",
    "StateCopy",
    "build_breakdown",
    "format_mapping_summary",
    "format_normalized_fields",
    "format_raw_log",
    "state_copy",
]
