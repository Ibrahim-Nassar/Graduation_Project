from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Event(StrictBaseModel):
    raw_event: str
    normalized_event: dict[str, Any]


class Entity(StrictBaseModel):
    type: str
    value: str
    start: int | None = None
    end: int | None = None
    evidence_ref: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_offsets(self) -> Entity:
        if (self.start is None) != (self.end is None):
            raise ValueError("start and end must either both be set or both be None")
        if self.start is not None and self.end is not None:
            if self.start < 0:
                raise ValueError("start must be >= 0")
            if self.end <= self.start:
                raise ValueError("end must be > start")
        return self


class AttackMapping(StrictBaseModel):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    evidence_strength: Literal["strong", "moderate", "weak"]
    rationale: str
    evidence_refs: list[str] = Field(min_length=1)


class EPC(StrictBaseModel):
    explain: str
    plan: list[str] = Field(min_length=1)
    checklist: list[str] = Field(min_length=2)
    citations: list[str] = Field(min_length=1)


class Result(StrictBaseModel):
    status: Literal["mapped", "no_mapping"]
    entities: list[Entity]
    attack_mapping: list[AttackMapping]
    epc: EPC | None
    audit: dict[str, Any]

    @model_validator(mode="after")
    def validate_status_consistency(self) -> Result:
        if self.status == "mapped":
            if len(self.attack_mapping) < 1:
                raise ValueError("status 'mapped' requires at least one attack_mapping")
            if self.epc is None:
                raise ValueError("status 'mapped' requires a non-None epc")
        else:
            if len(self.attack_mapping) != 0:
                raise ValueError("status 'no_mapping' requires an empty attack_mapping")
            if self.epc is not None:
                raise ValueError("status 'no_mapping' requires epc to be None")
        return self
