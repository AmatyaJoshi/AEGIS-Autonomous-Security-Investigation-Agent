"""Sigma match (+ triggering ECS event) -> OCSF ``detection_finding`` (SPEC §1.1, §3.2 normalize).

A ``SigmaMatch`` from :mod:`aegis.schema.normalize.sigma_match` plus the event it fired on becomes a
canonical alert. The finding's ``finding_info.uid`` is deterministic (rule id + event id) so the
same event/rule pair always yields the same alert id across online and offline runs.
"""

from __future__ import annotations

import hashlib
from typing import Any

from aegis.schema.normalize.ecs_to_ocsf import (
    actor_from_event,
    device_from_event,
    evidence_from_event,
    observables_from_event,
    parse_ts,
)
from aegis.schema.normalize.sigma_match import SigmaMatch
from aegis.schema.ocsf import (
    Analytic,
    Attack,
    DetectionFinding,
    FindingInfo,
    SeverityId,
    Tactic,
    Technique,
    new_metadata,
)

LEVEL_TO_SEVERITY: dict[str, SeverityId] = {
    "informational": SeverityId.INFORMATIONAL,
    "low": SeverityId.LOW,
    "medium": SeverityId.MEDIUM,
    "high": SeverityId.HIGH,
    "critical": SeverityId.CRITICAL,
}


def alert_uid(rule_id: str, event_id: str) -> str:
    return "al-" + hashlib.sha256(f"{rule_id}|{event_id}".encode()).hexdigest()[:20]


def finding_from_sigma(
    match: SigmaMatch, event: dict[str, Any], *, description: str | None = None
) -> DetectionFinding:
    severity = LEVEL_TO_SEVERITY.get(match.level, SeverityId.MEDIUM)
    attacks = [
        Attack(
            technique=Technique(uid=t),
            tactic=Tactic(uid=match.tactics[0].upper())
            if match.tactics and match.tactics[0].upper().startswith("TA")
            else None,
        )
        for t in match.techniques
    ] or ([Attack(tactic=Tactic(uid=match.tactics[0]))] if match.tactics else [])
    finding = DetectionFinding(
        time=parse_ts(event["@timestamp"]),
        metadata=new_metadata("Sigma", "SigmaHQ", labels=[f"sigma:{match.rule_id}"]),
        severity_id=severity,
        message=f"{match.title} on {event.get('host_name', 'unknown host')}",
        finding_info=FindingInfo(
            title=match.title,
            uid=alert_uid(match.rule_id, event["event_id"]),
            desc=description,
            analytic=Analytic(
                name=match.title, uid=match.rule_id, type="Rule", type_id=1, desc=description
            ),
            attacks=attacks,
            data_sources=[str(event.get("event_channel") or event.get("event_provider") or "")],
        ),
        observables=observables_from_event(event),
        evidences=[evidence_from_event(event, raw=event.get("raw"))],
        device=device_from_event(event),
        actor=actor_from_event(event),
        unmapped={
            "sigma_matched_fields": list(match.matched_fields),
            "dataset": event.get("dataset"),
            "dataset_ref": event.get("dataset_ref"),
        },
    )
    # Embed the full triggering ECS event so context/tools can re-query and cite it.
    if finding.evidences:
        clean = {k: v for k, v in event.items() if v is not None and k != "raw"}
        finding.evidences[0].data = {"raw": event.get("raw"), "ecs": clean}
    return finding
