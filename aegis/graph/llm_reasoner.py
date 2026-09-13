"""LLMReasoner: drives a frontier model through the versioned prompts (SPEC §3.2, §3.4).

Interchangeable with ``HeuristicReasoner``. Every model response is validated against a schema in
:mod:`aegis.llm.schemas`; the report is checked by the citation post-processor and re-prompted up to
twice. Evidence gathering still runs real scoped SIEM queries (the model designs the intent, the
tool enforces scoping). Falls back to the deterministic renderer if the model cannot produce a fully
cited report, so "evidence or silence" (§9.4) always holds.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from aegis.graph.citation import check_report
from aegis.graph.reasoner import HeuristicReasoner
from aegis.graph.report_util import render_markdown_report
from aegis.graph.state import ContextBundle, EvidenceRef, Hypothesis, TimelineEvent, Verdict
from aegis.llm.prompts_loader import load_prompt
from aegis.llm.router import LLMRouter
from aegis.llm.schemas import (
    EvidenceAssessment,
    HypothesesOut,
    ReportOut,
    VerdictOut,
)
from aegis.schema.ocsf import DetectionFinding
from aegis.siem.base import SiemAdapter, TimeWindow
from aegis.tools.siem_query import siem_query


class LLMReasoner:
    name = "llm"

    def __init__(self, router: LLMRouter) -> None:
        self.router = router
        self.system = load_prompt("system")
        self._fallback = HeuristicReasoner()

    def hypothesize(self, alert: DetectionFinding, context: ContextBundle) -> HypothesesOut:
        user = load_prompt("hypothesize").format(
            alert=_alert_json(alert), context=_ctx_json(context)
        )
        try:
            out = self.router.complete_schema(self.system, user, HypothesesOut)
        except ValueError:
            return self._fallback.hypothesize(alert, context)
        if not any(h.is_benign for h in out.hypotheses):
            out.hypotheses.append(self._fallback.hypothesize(alert, context).hypotheses[1])
        return out

    def assess_evidence(
        self,
        hypothesis: Hypothesis,
        alert: DetectionFinding,
        context: ContextBundle,
        siem: SiemAdapter,
    ) -> tuple[EvidenceAssessment, list[EvidenceRef]]:
        host = (alert.hostnames() or [""])[0]
        user = (alert.user_names() or [""])[0]
        window = TimeWindow(
            start=alert.time - timedelta(hours=1), end=alert.time + timedelta(hours=1)
        )
        entities = [e for e in (host, user) if e]
        refs: list[EvidenceRef] = []
        envelopes: list[str] = []
        for intent in (hypothesis.queries_run or ["process activity"])[:3] or ["process activity"]:
            res = siem_query(intent, entities, window, siem=siem, limit=40)
            envelopes.append(res.envelope)
            for r in res.data.get("rows", [])[:6]:
                refs.append(
                    EvidenceRef(
                        event_id=str(r.get("event_id")),
                        source="siem",
                        summary=str(r.get("process_command_line") or r.get("event_action") or ""),
                        fields=r,
                    )
                )
        user_prompt = load_prompt("evidence").format(
            hypothesis=hypothesis.statement, evidence="\n".join(envelopes)
        )
        try:
            assessment = self.router.complete_schema(self.system, user_prompt, EvidenceAssessment)
            assessment.hypothesis_id = hypothesis.id
        except ValueError:
            return self._fallback.assess_evidence(hypothesis, alert, context, siem)
        return assessment, refs

    def decide(
        self, alert: DetectionFinding, context: ContextBundle, hypotheses: list[Hypothesis]
    ) -> VerdictOut:
        user = load_prompt("verdict").format(
            alert=_alert_json(alert),
            context=_ctx_json(context),
            hypotheses=json.dumps([_hyp(h) for h in hypotheses]),
        )
        try:
            v = self.router.complete_schema(self.system, user, VerdictOut)
        except ValueError:
            return self._fallback.decide(alert, context, hypotheses)
        return v

    def write_report(
        self,
        alert: DetectionFinding,
        context: ContextBundle,
        hypotheses: list[Hypothesis],
        timeline: list[TimelineEvent],
        verdict: Verdict,
    ) -> ReportOut:
        valid = {
            ev
            for h in hypotheses
            for r in (h.evidence_for + h.evidence_against)
            for ev in [r.event_id]
        }
        valid |= {te.evidence.event_id for te in timeline}
        for ev in alert.evidences:
            valid.update(ev.event_uids)
        user = load_prompt("report").format(
            alert=_alert_json(alert),
            context=_ctx_json(context),
            hypotheses=json.dumps([_hyp(h) for h in hypotheses]),
            timeline=json.dumps([_tl(t) for t in timeline]),
            verdict=verdict.model_dump_json(),
        )
        for _ in range(2):
            try:
                out = self.router.complete_schema(self.system, user, ReportOut)
            except ValueError:
                break
            report = check_report(out.markdown, valid)
            if report.ok:
                return out
            user += (
                "\n\nYour previous report had uncited sentences: "
                f"{report.uncited_sentences[:3]}. Add a [E:<event_id>] to each."
            )
        # Evidence-or-silence: fall back to the always-cited deterministic renderer.
        return ReportOut(
            markdown=render_markdown_report(alert, context, hypotheses, timeline, verdict)
        )


def _alert_json(alert: DetectionFinding) -> str:
    return json.dumps(
        {
            "title": alert.finding_info.title,
            "severity": alert.severity,
            "techniques": alert.technique_ids,
            "host": alert.hostnames(),
            "user": alert.user_names(),
            "process": alert.actor.process.name if alert.actor and alert.actor.process else None,
            "command_line": alert.actor.process.cmd_line
            if alert.actor and alert.actor.process
            else None,
            "time": alert.time.isoformat(),
            "event_id": alert.evidences[0].event_uids[0]
            if alert.evidences and alert.evidences[0].event_uids
            else alert.alert_id,
        },
        default=str,
    )


def _ctx_json(context: ContextBundle) -> str:
    return context.model_dump_json()


def _hyp(h: Hypothesis) -> dict[str, Any]:
    return {
        "id": h.id,
        "statement": h.statement,
        "is_benign": h.is_benign,
        "status": h.status,
        "techniques": h.attack_techniques,
        "reasoning": h.reasoning,
        "evidence_for": [r.event_id for r in h.evidence_for],
        "evidence_against": [r.event_id for r in h.evidence_against],
    }


def _tl(t: TimelineEvent) -> dict[str, Any]:
    return {
        "ts": t.ts.isoformat() if t.ts else None,
        "description": t.description,
        "technique": t.technique,
        "event_id": t.evidence.event_id,
    }
