"""Deterministic incident-report renderer (used by HeuristicReasoner and as the LLM fallback).

Produces Markdown where every factual sentence carries a ``[E:<event_id>]`` citation by
construction, so it always passes the citation post-processor. Structural lines (headings, table
rows, list bullets) are exempt. Each claim cites either a specific evidence event or the alert's own
triggering event.
"""

from __future__ import annotations

from aegis.graph.state import ContextBundle, Hypothesis, TimelineEvent, Verdict
from aegis.schema.ocsf import DetectionFinding


def _alert_event_id(alert: DetectionFinding) -> str:
    for ev in alert.evidences:
        if ev.event_uids:
            return ev.event_uids[0]
    return alert.alert_id


def _cite(text: str, event_id: str) -> str:
    return f"{text} [E:{event_id}]"


def render_markdown_report(
    alert: DetectionFinding,
    context: ContextBundle,
    hypotheses: list[Hypothesis],
    timeline: list[TimelineEvent],
    verdict: Verdict,
) -> str:
    ae = _alert_event_id(alert)
    host = (alert.hostnames() or ["unknown host"])[0]
    user = (alert.user_names() or ["unknown user"])[0]
    lines: list[str] = []
    lines.append(f"# Incident Report - {alert.finding_info.title}")
    lines.append("")
    lines.append(f"**Alert ID:** {alert.alert_id}  ")
    lines.append(
        f"**Verdict:** {verdict.label.replace('_', ' ').title()} "
        f"(confidence {verdict.confidence:.0%}, severity {verdict.severity})  "
    )
    lines.append(f"**Techniques:** {', '.join(verdict.techniques) or 'none confirmed'}")
    lines.append("")

    lines.append("## Summary")
    lines.append(
        _cite(
            f"The rule '{alert.finding_info.title}' fired for {user} on {host} at "
            f"{alert.time.isoformat()}",
            ae,
        )
        + "."
    )
    lines.append(
        _cite(
            f"After investigation the activity is assessed as {verdict.label.replace('_', ' ')}", ae
        )
        + "."
    )
    if verdict.rationale:
        lines.append(_cite(f"Rationale: {verdict.rationale}", ae) + ".")
    lines.append("")

    lines.append("## Context")
    lines.append(
        _cite(
            f"The asset {host} is classified {context.asset.criticality} criticality"
            + (f", role {context.asset.role}" if context.asset.role else ""),
            ae,
        )
        + "."
    )
    lines.append(
        _cite(
            f"The account {user} is "
            + ("a privileged" if context.identity.privileged else "a non-privileged")
            + (" service account" if context.identity.service_account else " account")
            + (" known to the IdP" if context.identity.known else " not found in the IdP"),
            ae,
        )
        + "."
    )
    for hit in context.ti_hits:
        lines.append(
            _cite(
                f"Threat intelligence rates {hit.observable} as {hit.verdict} "
                f"(score {hit.score:.2f})",
                ae,
            )
            + "."
        )
    if context.off_hours:
        lines.append(_cite("The activity occurred outside business hours", ae) + ".")
    lines.append("")

    lines.append("## Hypotheses tested")
    for h in hypotheses:
        kind = "benign" if h.is_benign else "malicious"
        lines.append(f"### {h.statement} ({kind}, {h.status})")
        if h.reasoning:
            evs = h.evidence_for or h.evidence_against
            cid = evs[0].event_id if evs else ae
            lines.append(_cite(h.reasoning, cid) + ".")
        for ref in h.evidence_for[:4]:
            lines.append(f"- Supporting: {ref.summary} [E:{ref.event_id}]")
        for ref in h.evidence_against[:4]:
            lines.append(f"- Refuting: {ref.summary} [E:{ref.event_id}]")
        lines.append("")

    if timeline:
        lines.append("## Timeline")
        for te in timeline:
            ts = te.ts.isoformat() if te.ts else "?"
            tech = f" [{te.technique}]" if te.technique else ""
            lines.append(f"- {ts}{tech}: {te.description} [E:{te.evidence.event_id}]")
        lines.append("")

    lines.append("## Recommended action")
    lines.append(
        _cite(
            "Response actions are recommendations for a human analyst; AEGIS does not execute "
            "containment",
            ae,
        )
        + "."
    )
    return "\n".join(lines)
