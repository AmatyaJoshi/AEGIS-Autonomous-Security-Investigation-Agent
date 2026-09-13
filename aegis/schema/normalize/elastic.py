"""Elastic Security detection alert (`.alerts-security.alerts-*` doc) -> OCSF ``detection_finding``.

Elastic alert docs embed the ECS source event under ``kibana.alert.original_event`` / top-level ECS
fields plus ``kibana.alert.*`` metadata (rule name, severity, risk score, ATT&CK threat array).
This maps the pieces AEGIS needs; anything unmapped is preserved under ``unmapped``.
"""

from __future__ import annotations

from typing import Any

from aegis.schema.normalize.ecs_to_ocsf import (
    actor_from_event,
    device_from_event,
    evidence_from_event,
    observables_from_event,
    parse_ts,
)
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

_SEV = {
    "low": SeverityId.LOW,
    "medium": SeverityId.MEDIUM,
    "high": SeverityId.HIGH,
    "critical": SeverityId.CRITICAL,
}


def _flatten_ecs(doc: dict[str, Any]) -> dict[str, Any]:
    """Turn a nested ECS alert source into the flat row shape our extractors expect."""

    def g(*path: str) -> Any:
        cur: Any = doc
        for p in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
        return cur

    return {
        "event_id": doc.get("_id") or g("kibana.alert.uuid") or g("event", "id"),
        "@timestamp": doc.get("@timestamp"),
        "host_name": g("host", "name"),
        "host_os_type": g("host", "os", "type"),
        "user_name": g("user", "name"),
        "user_domain": g("user", "domain"),
        "process_name": g("process", "name"),
        "process_executable": g("process", "executable"),
        "process_command_line": g("process", "command_line"),
        "process_pid": g("process", "pid"),
        "process_parent_name": g("process", "parent", "name"),
        "process_parent_executable": g("process", "parent", "executable"),
        "process_hash_sha256": g("process", "hash", "sha256"),
        "source_ip": g("source", "ip"),
        "destination_ip": g("destination", "ip"),
        "file_path": g("file", "path"),
        "dns_question_name": g("dns", "question", "name"),
        "event_channel": g("winlog", "channel"),
        "raw": None,
    }


def finding_from_elastic(alert: dict[str, Any]) -> DetectionFinding:
    src = alert.get("_source", alert)
    ev = _flatten_ecs({**src, "_id": alert.get("_id")})
    rule_name = (
        _get(src, "kibana.alert.rule.name") or _get(src, "signal.rule.name") or "Elastic Rule"
    )
    severity = str(
        _get(src, "kibana.alert.severity") or _get(src, "signal.rule.severity") or "medium"
    ).lower()
    threats = _get(src, "kibana.alert.rule.threat") or _get(src, "signal.rule.threat") or []
    attacks: list[Attack] = []
    for th in threats:
        for tech in th.get("technique", []) or []:
            attacks.append(
                Attack(
                    technique=Technique(uid=str(tech.get("id"))) if tech.get("id") else None,
                    tactic=Tactic(uid=str(th.get("tactic", {}).get("id")))
                    if th.get("tactic")
                    else None,
                )
            )
    return DetectionFinding(
        time=parse_ts(ev["@timestamp"]),
        metadata=new_metadata(
            "Elastic Security",
            "Elastic",
            labels=[f"elastic:{_get(src, 'kibana.alert.rule.uuid') or ''}"],
        ),
        severity_id=_SEV.get(severity, SeverityId.MEDIUM),
        message=str(_get(src, "kibana.alert.reason") or rule_name),
        finding_info=FindingInfo(
            title=str(rule_name),
            uid=str(ev["event_id"]),
            desc=_get(src, "kibana.alert.rule.description"),
            analytic=Analytic(
                name=str(rule_name), type="Rule", type_id=1, uid=_get(src, "kibana.alert.rule.uuid")
            ),
            attacks=attacks,
        ),
        observables=observables_from_event(ev),
        evidences=[evidence_from_event(ev)],
        device=device_from_event(ev),
        actor=actor_from_event(ev),
        unmapped={"source": "elastic"},
    )


def _get(doc: dict[str, Any], dotted: str) -> Any:
    # Elastic docs may store either nested objects or dotted-key fields; try both.
    if dotted in doc:
        return doc[dotted]
    cur: Any = doc
    for p in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur
