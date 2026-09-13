"""Structured-output schemas every LLM node validates against (SPEC §3, CLAUDE.md).

Each node asks the model for JSON matching one of these schemas; the router parses and validates the
response into the model, retrying on validation failure. Nothing downstream ever sees raw model
text - only validated structures - so a malformed or injected response cannot corrupt state.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class HypothesisOut(BaseModel):
    statement: str
    attack_techniques: list[str] = Field(default_factory=list)
    prior: float = 0.3
    is_benign: bool = False
    queries_to_run: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("prior")
    @classmethod
    def _clamp(cls, v: float) -> float:
        return max(0.0, min(1.0, v))

    @field_validator("attack_techniques")
    @classmethod
    def _upper(cls, v: list[str]) -> list[str]:
        return [t.strip().upper() for t in v if t.strip()]


class HypothesesOut(BaseModel):
    hypotheses: list[HypothesisOut] = Field(min_length=1, max_length=6)


class EvidenceAssessment(BaseModel):
    """One hypothesis's verdict after querying, with the event ids it relies on."""

    hypothesis_id: str
    status: Literal["supported", "refuted", "inconclusive"]
    supporting_event_ids: list[str] = Field(default_factory=list)
    refuting_event_ids: list[str] = Field(default_factory=list)
    reasoning: str = ""


class TimelineEntryOut(BaseModel):
    event_id: str
    description: str
    technique: str | None = None


class TimelineOut(BaseModel):
    entries: list[TimelineEntryOut] = Field(default_factory=list)


class VerdictOut(BaseModel):
    label: Literal["true_positive", "false_positive", "escalate"]
    confidence: float
    severity: Literal["critical", "high", "medium", "low", "informational"]
    techniques: list[str] = Field(default_factory=list)
    rationale: str

    @field_validator("confidence")
    @classmethod
    def _clamp(cls, v: float) -> float:
        return max(0.0, min(1.0, v))

    @field_validator("techniques")
    @classmethod
    def _upper(cls, v: list[str]) -> list[str]:
        return [t.strip().upper() for t in v if t.strip()]


class ReportOut(BaseModel):
    """Markdown report; the citation post-processor enforces the [E:<id>] rule separately."""

    markdown: str
