"""Investigation graph nodes (SPEC §3.2). Each factory closes over ``Deps`` and returns a node fn.

Nodes are deterministic wrappers around the reasoner and tools; all reasoning that could vary by
backend lives in the reasoner, so the graph shape is identical online and offline.
"""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

from aegis.graph.deps import Deps
from aegis.graph.state import (
    AssetInfo,
    Budget,
    ContextBundle,
    EvidenceRef,
    Hypothesis,
    IdentityInfo,
    InvestigationState,
    TIHit,
    TimelineEvent,
    Verdict,
)
from aegis.schema.ocsf import DetectionFinding, ObservableTypeId
from aegis.security.injection_guard import scan_fields
from aegis.siem.base import TimeWindow
from aegis.tools.asset_lookup import asset_lookup, identity_lookup
from aegis.tools.attack_kb import validate_techniques
from aegis.tools.sigma_match import sigma_match
from aegis.tools.ti_lookup import ti_lookup


def make_normalize(deps: Deps):  # type: ignore[no-untyped-def]
    def normalize(state: InvestigationState) -> dict[str, Any]:
        alert = state["alert"]
        guard = scan_fields(alert.free_text_fields())
        return {
            "injection_flags": guard.flags,
            "node_log": ["normalize"],
            "spent": _bump(state, tool_calls=0),
        }

    return normalize


def make_context(deps: Deps):  # type: ignore[no-untyped-def]
    def context(state: InvestigationState) -> dict[str, Any]:
        alert = state["alert"]
        hosts = alert.hostnames()
        users = alert.user_names()
        host = hosts[0] if hosts else None
        user = users[0] if users else None
        tool_calls = 0
        asset = AssetInfo()
        if host:
            a = asset_lookup(host, deps.org_path).data
            asset = AssetInfo(
                host=a.get("host"),
                known=a.get("known", False),
                criticality=a.get("criticality", "unknown"),
                role=a.get("role"),
                owner=a.get("owner"),
                os=a.get("os"),
            )
            tool_calls += 1
        identity = IdentityInfo()
        if user:
            i = identity_lookup(user, deps.org_path).data
            identity = IdentityInfo(
                user=i.get("user"),
                known=i.get("known", False),
                privileged=i.get("privileged", False),
                service_account=i.get("service_account", False),
                role=i.get("role"),
                service=i.get("service"),
            )
            tool_calls += 1
        ti_hits: list[TIHit] = []
        for obs in alert.observables:
            if (
                obs.type_id
                in (ObservableTypeId.IP_ADDRESS, ObservableTypeId.HOSTNAME, ObservableTypeId.HASH)
                and obs.value
            ):
                if obs.type_id == ObservableTypeId.HOSTNAME and "." not in obs.value:
                    continue  # bare internal hostname, not a domain
                r = ti_lookup(obs.value, cache_dir=deps.intel_cache_dir, provider=deps.intel).data
                tool_calls += 1
                if r.get("verdict") not in (None, "unknown", "benign"):
                    ti_hits.append(
                        TIHit(
                            observable=obs.value,
                            type=r.get("type", "unknown"),
                            verdict=r["verdict"],
                            score=r.get("score", 0.0),
                            categories=r.get("categories", []),
                        )
                    )
        rematch: list[str] = []
        raw_event = _triggering_event(alert)
        if raw_event:
            sm = sigma_match(raw_event, pack_path=deps.pack_path).data
            rematch = [m["title"] for m in sm.get("matches", [])]
            tool_calls += 1
        off_hours = _off_hours(alert, deps.business_hours)
        bundle = ContextBundle(
            asset=asset,
            identity=identity,
            ti_hits=ti_hits,
            sigma_rematch=rematch,
            off_hours=off_hours,
            recent_alert_count=0,
        )
        return {"context": bundle, "node_log": ["context"], "spent": _bump(state, tool_calls)}

    return context


def make_triage_pre(deps: Deps):  # type: ignore[no-untyped-def]
    def triage_pre(state: InvestigationState) -> dict[str, Any]:
        if deps.triage is None:
            return {"node_log": ["triage_pre:skip"]}
        alert = state["alert"]
        ctx = state["context"]
        from aegis.models.triage import serialize_features

        feats = serialize_features(alert, ctx)
        scores = deps.triage.score(feats)
        low_sev = str(alert.severity_id.name).lower() in ("low", "informational", "medium")
        if scores.get("p_fp", 0.0) > deps.fast_path_pfp and low_sev and not ctx.ti_hits:
            verdict = Verdict(
                label="false_positive",
                confidence=scores["p_fp"],
                severity="informational",
                techniques=[],
                fast_pathed=True,
                triage_model_score=scores["p_fp"],
                llm_score=None,
                rationale=f"Fast-pathed by triage model (p_fp={scores['p_fp']:.3f})",
            )
            return {"verdict": verdict, "node_log": ["triage_pre:fast_path"]}
        return {"node_log": ["triage_pre:continue"]}

    return triage_pre


def make_hypothesize(deps: Deps):  # type: ignore[no-untyped-def]
    def hypothesize(state: InvestigationState) -> dict[str, Any]:
        if state.get("verdict") is not None:  # fast-pathed
            return {}
        alert = state["alert"]
        out = deps.reasoner.hypothesize(alert, state["context"])
        hyps = [
            Hypothesis(
                id=f"H{i + 1}",
                statement=h.statement,
                attack_techniques=h.attack_techniques,
                prior=h.prior,
                is_benign=h.is_benign,
                queries_run=h.queries_to_run,
            )
            for i, h in enumerate(out.hypotheses)
        ]
        return {"hypotheses": hyps, "node_log": ["hypothesize"], "spent": _bump(state, llm_calls=1)}

    return hypothesize


def make_evidence(deps: Deps):  # type: ignore[no-untyped-def]
    def evidence(state: InvestigationState) -> dict[str, Any]:
        if state.get("verdict") is not None:
            return {}
        alert = state["alert"]
        ctx = state["context"]
        assessed: list[Hypothesis] = []
        tool_calls = 0
        for h in state.get("hypotheses", []):
            assessment, refs = deps.reasoner.assess_evidence(h, alert, ctx, deps.siem)
            tool_calls += 1
            by_id = {r.event_id: r for r in refs}
            h.status = assessment.status
            h.reasoning = assessment.reasoning
            h.evidence_for = [by_id[i] for i in assessment.supporting_event_ids if i in by_id]
            h.evidence_against = [by_id[i] for i in assessment.refuting_event_ids if i in by_id]
            if not h.evidence_for and not h.evidence_against and refs:
                (h.evidence_for if h.status == "supported" else h.evidence_against).extend(refs[:2])
            assessed.append(h)
        return {
            "hypotheses": assessed,
            "node_log": ["evidence"],
            "spent": _bump(state, tool_calls=tool_calls, llm_calls=len(assessed)),
        }

    return evidence


def make_timeline(deps: Deps):  # type: ignore[no-untyped-def]
    def timeline(state: InvestigationState) -> dict[str, Any]:
        v0 = state.get("verdict")
        if v0 is not None and v0.fast_pathed:
            return {"timeline": []}
        alert = state["alert"]
        refs: dict[str, EvidenceRef] = {}
        for h in state.get("hypotheses", []):
            for r in h.evidence_for + h.evidence_against:
                refs.setdefault(r.event_id, r)
        events: list[TimelineEvent] = []
        for r in refs.values():
            fields = r.fields
            ts = _parse(fields.get("@timestamp"))
            events.append(
                TimelineEvent(
                    ts=ts,
                    host=fields.get("host_name"),
                    user=fields.get("user_name"),
                    process=fields.get("process_name"),
                    description=r.summary or str(fields.get("event_action") or "event"),
                    technique=None,
                    evidence=r,
                )
            )
        events.sort(key=lambda e: (e.ts is None, e.ts or alert.time))
        return {"timeline": events[:50], "node_log": ["timeline"]}

    return timeline


def make_attack_map(deps: Deps):  # type: ignore[no-untyped-def]
    def attack_map(state: InvestigationState) -> dict[str, Any]:
        alert = state["alert"]
        candidates: list[str] = list(alert.technique_ids)
        for h in state.get("hypotheses", []):
            if not h.is_benign and h.status in ("supported", "inconclusive"):
                candidates.extend(h.attack_techniques)
        valid, _invalid = validate_techniques(list(dict.fromkeys(candidates)))
        return {"validated_techniques": valid, "node_log": ["attack_map"]}

    return attack_map


def make_verdict(deps: Deps):  # type: ignore[no-untyped-def]
    def verdict(state: InvestigationState) -> dict[str, Any]:
        v0 = state.get("verdict")
        if v0 is not None and v0.fast_pathed:
            return {"node_log": ["verdict:fast_path"]}
        alert = state["alert"]
        ctx = state["context"]
        hyps = state.get("hypotheses", [])
        flags = state.get("injection_flags", [])
        budget = state.get("budget", Budget())
        spent = state.get("spent", Budget())
        # Injection detected -> escalate (SPEC §3.2, §9.3).
        high_flag = any(f.severity in ("medium", "high") for f in flags)
        v_out = deps.reasoner.decide(alert, ctx, hyps)
        valid = state.get("validated_techniques", v_out.techniques)
        techniques = [t for t in v_out.techniques if t in valid] or valid
        label = v_out.label
        rationale = v_out.rationale
        if high_flag:
            label = "escalate"
            rationale = (
                "Prompt-injection detected in log content; escalating for human review. "
                + rationale
            )
        if spent.exceeded(budget):
            label = "escalate"
            rationale = (
                "Investigation budget exceeded; escalating with partial results. " + rationale
            )
        malicious_score = _malicious_score(label, v_out.confidence)
        triage_score = None
        confidence = v_out.confidence
        if deps.triage is not None:
            from aegis.models.triage import serialize_features

            scores = deps.triage.score(serialize_features(alert, ctx))
            triage_score = scores.get("p_tp")
            if triage_score is not None:
                blended = 0.6 * malicious_score + 0.4 * triage_score
                malicious_score = blended
        verdict_obj = Verdict(
            label=label,
            confidence=confidence,
            severity=v_out.severity,
            techniques=techniques,
            rationale=rationale,
            triage_model_score=triage_score,
            llm_score=malicious_score,
        )
        return {"verdict": verdict_obj, "node_log": ["verdict"], "spent": _bump(state, llm_calls=1)}

    return verdict


def make_report(deps: Deps):  # type: ignore[no-untyped-def]
    def report(state: InvestigationState) -> dict[str, Any]:
        alert = state["alert"]
        ctx = state["context"]
        v = state["verdict"]
        assert v is not None
        hyps = state.get("hypotheses", [])
        tl = state.get("timeline", [])
        if v.fast_pathed:
            from aegis.graph.report_util import render_markdown_report

            md = render_markdown_report(alert, ctx, hyps, tl, v)
        else:
            md = deps.reasoner.write_report(alert, ctx, hyps, tl, v).markdown
        from aegis.graph.citation import check_report

        valid = _valid_ids(state)
        cr = check_report(md, valid)
        report_json = {
            "alert_id": alert.alert_id,
            "verdict": v.model_dump(mode="json"),
            "hypotheses": [h.model_dump(mode="json") for h in hyps],
            "citations_ok": cr.ok,
            "uncited": cr.uncited_sentences[:5],
        }
        return {
            "report_md": md,
            "report_json": report_json,
            "node_log": [f"report:cited={cr.ok}"],
            "spent": _bump(state, llm_calls=1),
        }

    return report


def make_playbook(deps: Deps):  # type: ignore[no-untyped-def]
    def playbook(state: InvestigationState) -> dict[str, Any]:
        from aegis.graph.playbooks import select_playbook

        v = state["verdict"]
        assert v is not None
        pb = select_playbook(v.label, v.techniques, state["context"].asset.criticality)
        return {
            "playbook_id": pb.get("id") if pb else None,
            "playbook": pb,
            "node_log": ["playbook"],
        }

    return playbook


# ------------------------------------------------------------------------------------------------
def _bump(state: InvestigationState, tool_calls: int = 0, llm_calls: int = 0) -> Budget:
    spent = state.get("spent") or Budget()
    return Budget(
        tool_calls=spent.tool_calls + tool_calls,
        llm_calls=spent.llm_calls + llm_calls,
        tokens=spent.tokens,
        wall_clock_s=spent.wall_clock_s,
        cost_usd=spent.cost_usd,
    )


def _triggering_event(alert: DetectionFinding) -> dict[str, Any] | None:
    for ev in alert.evidences:
        data = ev.data or {}
        ecs = data.get("ecs")
        if isinstance(ecs, dict) and ecs.get("event_id"):
            return ecs
        if ev.event_uids:
            return {"event_id": ev.event_uids[0], **(ecs or {})}
    return None


def _off_hours(alert: DetectionFinding, hours: tuple[int, int]) -> bool:
    h = alert.time.hour
    return alert.time.weekday() >= 5 or h < hours[0] or h >= hours[1]


def _malicious_score(label: str, confidence: float) -> float:
    if label == "true_positive":
        return 0.5 + confidence / 2
    if label == "false_positive":
        return max(0.0, 0.5 - confidence / 2)
    return 0.5


def _valid_ids(state: InvestigationState) -> set[str]:
    ids: set[str] = set()
    for h in state.get("hypotheses", []):
        for r in h.evidence_for + h.evidence_against:
            ids.add(r.event_id)
    for te in state.get("timeline", []):
        ids.add(te.evidence.event_id)
    for ev in state["alert"].evidences:
        ids.update(ev.event_uids)
    return ids


def _parse(v: Any):  # type: ignore[no-untyped-def]
    from datetime import datetime

    if isinstance(v, datetime):
        return v
    if v is None:
        return None
    try:
        from dateutil import parser as dtp

        return dtp.parse(str(v))
    except (ValueError, TypeError):
        return None


_ = TimeWindow, timedelta, time  # keep imports meaningful for future live-mode use
