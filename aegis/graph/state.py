"""LangGraph investigation state (SPEC §3.1).

The state is a ``TypedDict`` (LangGraph's channel model) whose OCSF-typed members are Pydantic
models - never raw dicts (CLAUDE.md). Reducer annotations let fan-out nodes (per-hypothesis
evidence) append concurrently.
"""

from __future__ import annotations

import operator
from datetime import datetime
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, Field

from aegis.schema.ocsf import DetectionFinding
from aegis.security.injection_guard import InjectionFlag


class EvidenceRef(BaseModel):
    event_id: str
    source: str
    timestamp: datetime | None = None
    summary: str = ""
    fields: dict[str, Any] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    id: str
    statement: str
    attack_techniques: list[str] = Field(default_factory=list)
    prior: float = 0.3
    is_benign: bool = False
    status: Literal["open", "supported", "refuted", "inconclusive"] = "open"
    evidence_for: list[EvidenceRef] = Field(default_factory=list)
    evidence_against: list[EvidenceRef] = Field(default_factory=list)
    queries_run: list[str] = Field(default_factory=list)
    reasoning: str = ""


class TimelineEvent(BaseModel):
    ts: datetime | None = None
    host: str | None = None
    user: str | None = None
    process: str | None = None
    description: str
    technique: str | None = None
    evidence: EvidenceRef


class Verdict(BaseModel):
    label: Literal["true_positive", "false_positive", "escalate"]
    confidence: float
    severity: Literal["critical", "high", "medium", "low", "informational"]
    techniques: list[str] = Field(default_factory=list)
    rationale: str = ""
    triage_model_score: float | None = None
    llm_score: float | None = None
    fast_pathed: bool = False


class AssetInfo(BaseModel):
    host: str | None = None
    known: bool = False
    criticality: str = "unknown"
    role: str | None = None
    owner: str | None = None
    os: str | None = None


class IdentityInfo(BaseModel):
    user: str | None = None
    known: bool = False
    privileged: bool = False
    service_account: bool = False
    role: str | None = None
    service: str | None = None


class TIHit(BaseModel):
    observable: str
    type: str
    verdict: str
    score: float
    categories: list[str] = Field(default_factory=list)


class ContextBundle(BaseModel):
    asset: AssetInfo = Field(default_factory=AssetInfo)
    identity: IdentityInfo = Field(default_factory=IdentityInfo)
    ti_hits: list[TIHit] = Field(default_factory=list)
    recent_alert_count: int = 0
    sigma_rematch: list[str] = Field(default_factory=list)
    off_hours: bool = False
    notes: list[str] = Field(default_factory=list)


class Budget(BaseModel):
    tool_calls: int = 0
    llm_calls: int = 0
    tokens: int = 0
    wall_clock_s: float = 0.0
    cost_usd: float = 0.0

    def exceeded(self, cap: Budget) -> bool:
        return (
            self.tool_calls > cap.tool_calls
            or self.llm_calls > cap.llm_calls
            or self.tokens > cap.tokens
            or self.wall_clock_s > cap.wall_clock_s
        )


DEFAULT_BUDGET = Budget(tool_calls=40, llm_calls=12, tokens=120_000, wall_clock_s=120.0)


class InvestigationState(TypedDict, total=False):
    investigation_id: str
    alert: DetectionFinding
    context: ContextBundle
    hypotheses: list[Hypothesis]
    validated_techniques: list[str]
    timeline: list[TimelineEvent]
    verdict: Verdict | None
    report_md: str | None
    report_json: dict[str, Any] | None
    playbook_id: str | None
    playbook: dict[str, Any] | None
    budget: Budget
    spent: Budget
    injection_flags: Annotated[list[InjectionFlag], operator.add]
    errors: Annotated[list[str], operator.add]
    review_mode: bool
    node_log: Annotated[list[str], operator.add]
