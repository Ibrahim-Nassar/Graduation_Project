from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from src.contracts import StrictBaseModel
from src.feedback import CorrectionRecord


class ExportedTrainingRow(StrictBaseModel):
    text: str = Field(min_length=1)
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    source: str | None = None
    label_origin: Literal["analyst_correction"]
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)


def export_training_dataset(input_path: Path | str, output_path: Path | str) -> list[dict[str, Any]]:
    source_path = Path(input_path)
    target_path = Path(output_path)

    rows: list[dict[str, Any]] = []
    for line in source_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        correction_payload = json.loads(line)
        correction = CorrectionRecord.model_validate(correction_payload)

        for mapping in correction.corrected_attack_mapping:
            row = ExportedTrainingRow(
                text=correction.raw_event,
                technique_id=mapping.technique_id,
                technique_name=mapping.technique_name,
                source=correction.source_fixture,
                label_origin="analyst_correction",
                rationale=mapping.rationale,
                confidence=mapping.confidence,
            )
            rows.append(row.model_dump(mode="json"))

    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8") as output:
        for row in rows:
            output.write(json.dumps(row, sort_keys=True) + "\n")

    return rows
