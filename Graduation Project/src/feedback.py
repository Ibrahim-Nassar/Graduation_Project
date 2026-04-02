from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from src.contracts import AttackMapping, Entity, Result, StrictBaseModel

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CORRECTIONS_FILE = "corrections.jsonl"


class CorrectionRecord(StrictBaseModel):
    raw_event: str
    normalized_event: dict[str, Any]
    entities: list[Entity]
    original_attack_mapping: list[AttackMapping] = Field(min_length=1)
    corrected_attack_mapping: list[AttackMapping] = Field(min_length=1)
    analyst_note: str | None = None
    created_at: str
    source_fixture: str | None = None

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: str) -> str:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("created_at must include UTC timezone information")
        if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError("created_at must be UTC")
        return value


def _utc_iso8601_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def save_correction(
    result: Result,
    corrected_attack_mapping: list[dict],
    analyst_note: str | None = None,
    source_fixture: str | None = None,
) -> dict[str, Any]:
    validated_corrected = [AttackMapping.model_validate(item) for item in corrected_attack_mapping]
    normalized_event = result.audit.get("normalized_event", {})
    raw_event = result.audit.get("raw_event", "")

    record = CorrectionRecord(
        raw_event=raw_event,
        normalized_event=normalized_event,
        entities=result.entities,
        original_attack_mapping=result.attack_mapping,
        corrected_attack_mapping=validated_corrected,
        analyst_note=analyst_note,
        created_at=_utc_iso8601_timestamp(),
        source_fixture=source_fixture,
    )

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    output_path = DATA_DIR / CORRECTIONS_FILE
    serialized = json.dumps(record.model_dump(mode="json"), sort_keys=True)
    with output_path.open("a", encoding="utf-8") as output:
        output.write(serialized + "\n")

    return record.model_dump(mode="json")
