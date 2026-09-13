"""Shared context enrichment used by both the graph's ``context`` node and triage dataset building.

Runs asset/identity lookups, threat-intel enrichment, Sigma re-match and off-hours checks to
produce a ``ContextBundle`` for an alert. Extracted so the triage model (§7.1) trains on exactly
the same features the live graph uses at inference time.
"""

from __future__ import annotations

from typing import Any

from aegis.graph.deps import Deps
from aegis.graph.state import AssetInfo, ContextBundle, IdentityInfo, TIHit
from aegis.schema.ocsf import DetectionFinding, ObservableTypeId
from aegis.tools.asset_lookup import asset_lookup, identity_lookup
from aegis.tools.sigma_match import sigma_match
from aegis.tools.ti_lookup import ti_lookup


def off_hours(alert: DetectionFinding, hours: tuple[int, int]) -> bool:
    h = alert.time.hour
    return alert.time.weekday() >= 5 or h < hours[0] or h >= hours[1]


def triggering_event(alert: DetectionFinding) -> dict[str, Any] | None:
    for ev in alert.evidences:
        data = ev.data or {}
        ecs = data.get("ecs")
        if isinstance(ecs, dict) and ecs.get("event_id"):
            return ecs
        if ev.event_uids:
            return {"event_id": ev.event_uids[0], **(ecs or {})}
    return None


def build_context(alert: DetectionFinding, deps: Deps) -> tuple[ContextBundle, int]:
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
                continue
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
    raw_event = triggering_event(alert)
    if raw_event:
        sm = sigma_match(raw_event, pack_path=deps.pack_path).data
        rematch = [m["title"] for m in sm.get("matches", [])]
        tool_calls += 1
    return ContextBundle(
        asset=asset,
        identity=identity,
        ti_hits=ti_hits,
        sigma_rematch=rematch,
        off_hours=off_hours(alert, deps.business_hours),
        recent_alert_count=0,
    ), tool_calls
