"""Assemble the LangGraph investigation StateGraph (SPEC §3.3).

Edges: normalize -> context -> triage_pre -> (fast-path) verdict | hypothesize -> evidence ->
timeline -> attack_map -> verdict -> report -> playbook -> END. A budget guard short-circuits to
verdict with partial results. ``interrupt_before=["playbook"]`` in review mode.

The checkpointer makes investigations resumable/replayable (SPEC §2.1): a SqliteSaver by default
(no server needed), swappable for the Postgres checkpointer in production.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from aegis.graph.deps import Deps
from aegis.graph.nodes.core import (
    make_attack_map,
    make_context,
    make_evidence,
    make_hypothesize,
    make_normalize,
    make_playbook,
    make_report,
    make_timeline,
    make_triage_pre,
    make_verdict,
)
from aegis.graph.state import Budget, InvestigationState


def _route_after_triage(state: InvestigationState) -> str:
    v = state.get("verdict")
    if v is not None and v.fast_pathed:
        return "verdict"
    return "hypothesize"


def _budget_guard(next_node: str):  # type: ignore[no-untyped-def]
    def route(state: InvestigationState) -> str:
        spent = state.get("spent") or Budget()
        budget = state.get("budget") or Budget()
        if spent.exceeded(budget):
            return "verdict"
        return next_node

    return route


def build_graph(deps: Deps, checkpointer: Any | None = None) -> Any:
    g: StateGraph[InvestigationState, None, InvestigationState, InvestigationState] = StateGraph(
        InvestigationState
    )
    g.add_node("normalize", make_normalize(deps))
    g.add_node("context", make_context(deps))
    g.add_node("triage_pre", make_triage_pre(deps))
    g.add_node("hypothesize", make_hypothesize(deps))
    g.add_node("evidence", make_evidence(deps))
    g.add_node("timeline", make_timeline(deps))
    g.add_node("attack_map", make_attack_map(deps))
    g.add_node("verdict", make_verdict(deps))
    g.add_node("report", make_report(deps))
    g.add_node("playbook", make_playbook(deps))

    g.set_entry_point("normalize")
    g.add_edge("normalize", "context")
    g.add_edge("context", "triage_pre")
    g.add_conditional_edges(
        "triage_pre", _route_after_triage, {"verdict": "verdict", "hypothesize": "hypothesize"}
    )
    g.add_conditional_edges(
        "hypothesize", _budget_guard("evidence"), {"evidence": "evidence", "verdict": "verdict"}
    )
    g.add_edge("evidence", "timeline")
    g.add_edge("timeline", "attack_map")
    g.add_edge("attack_map", "verdict")
    g.add_edge("verdict", "report")
    g.add_edge("report", "playbook")
    g.add_edge("playbook", END)

    kwargs: dict[str, Any] = {}
    if checkpointer is not None:
        kwargs["checkpointer"] = checkpointer
    if deps.review_mode:
        kwargs["interrupt_before"] = ["playbook"]
    return g.compile(**kwargs)
