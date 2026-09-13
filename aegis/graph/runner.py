"""High-level investigation runner: build state, invoke the graph, collect a typed result.

Used by the CLI (``aegis investigate``), the benchmark arms and the API. Handles telemetry spans and
converts the LangGraph output back into typed models.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from aegis.graph.build import build_graph
from aegis.graph.deps import Deps
from aegis.graph.state import (
    DEFAULT_BUDGET,
    Budget,
    ContextBundle,
    Hypothesis,
    InvestigationState,
    TimelineEvent,
    Verdict,
)
from aegis.llm.prompts_loader import prompt_versions
from aegis.schema.ocsf import DetectionFinding
from aegis.telemetry.otel import span


@dataclass
class InvestigationResult:
    investigation_id: str
    alert: DetectionFinding
    verdict: Verdict | None
    context: ContextBundle
    hypotheses: list[Hypothesis]
    timeline: list[TimelineEvent]
    report_md: str | None
    report_json: dict[str, Any] | None
    playbook_id: str | None
    playbook: dict[str, Any] | None
    injection_flagged: bool
    spent: Budget
    seconds: float
    node_log: list[str] = field(default_factory=list)
    prompt_versions: dict[str, int] = field(default_factory=dict)

    @property
    def malicious_score(self) -> float:
        if self.verdict is None:
            return 0.5
        return (
            self.verdict.llm_score
            if self.verdict.llm_score is not None
            else (
                self.verdict.confidence
                if self.verdict.label == "true_positive"
                else 1 - self.verdict.confidence
                if self.verdict.label == "false_positive"
                else 0.5
            )
        )


def run_investigation(
    alert: DetectionFinding,
    deps: Deps,
    *,
    budget: Budget | None = None,
    checkpointer: Any | None = None,
    investigation_id: str | None = None,
) -> InvestigationResult:
    inv_id = investigation_id or f"inv-{uuid.uuid4().hex[:12]}"
    graph = build_graph(deps, checkpointer=checkpointer)
    init: InvestigationState = {
        "investigation_id": inv_id,
        "alert": alert,
        "budget": budget or DEFAULT_BUDGET,
        "spent": Budget(),
        "hypotheses": [],
        "timeline": [],
        "injection_flags": [],
        "errors": [],
        "node_log": [],
        "review_mode": deps.review_mode,
    }
    config = {"configurable": {"thread_id": inv_id}}
    t0 = time.perf_counter()
    with span(
        "aegis.investigation",
        **{"aegis.investigation_id": inv_id, "aegis.alert_id": alert.alert_id},
    ):
        final: InvestigationState = graph.invoke(init, config=config)
    elapsed = time.perf_counter() - t0
    verdict = final.get("verdict")
    return InvestigationResult(
        investigation_id=inv_id,
        alert=alert,
        verdict=verdict,
        context=final.get("context") or ContextBundle(),
        hypotheses=final.get("hypotheses", []),
        timeline=final.get("timeline", []),
        report_md=final.get("report_md"),
        report_json=final.get("report_json"),
        playbook_id=final.get("playbook_id"),
        playbook=final.get("playbook"),
        injection_flagged=bool(final.get("injection_flags")),
        spent=final.get("spent") or Budget(),
        seconds=elapsed,
        node_log=final.get("node_log", []),
        prompt_versions=prompt_versions(),
    )
