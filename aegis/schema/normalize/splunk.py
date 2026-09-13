"""Splunk notable / correlation-search result -> OCSF detection_finding.

Splunk notables are flat key/value results (``search_name``, ``urgency``,
``annotations.mitre_attack``
plus CIM/raw fields). This maps the common Enterprise Security notable shape.
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
    Technique,
    new_metadata,
)

_URGENCY = {
    "informational": SeverityId.INFORMATIONAL,
    "low": SeverityId.LOW,
    "medium": SeverityId.MEDIUM,
    "high": SeverityId.HIGH,
    "critical": SeverityId.CRITICAL,
}


def _row(n: dict[str, Any]) -> dict[str, Any]:
    def first(*keys: str) -> Any:
        for k in keys:
            if n.get(k) not in (None, ""):
                return n[k]
        return None

    return {
        "event_id": first("event_id", "_cd", "orig_rid") or n.get("_time"),
        "@timestamp": first("_time", "timestamp", "firstTime"),
        "host_name": first("dest", "host", "dest_nt_host", "Computer"),
        "user_name": first("user", "src_user", "User"),
        "process_name": first("process_name", "Image"),
        "process_command_line": first("process", "CommandLine", "command_line"),
        "process_parent_name": first("parent_process_name", "ParentImage"),
        "process_hash_sha256": first("file_hash", "sha256"),
        "source_ip": first("src_ip", "src"),
        "destination_ip": first("dest_ip"),
        "file_path": first("file_path", "TargetFilename"),
        "raw": n.get("_raw"),
    }


def finding_from_splunk(notable: dict[str, Any]) -> DetectionFinding:
    ev = _row(notable)
    name = str(notable.get("search_name") or notable.get("rule_name") or "Splunk Notable")
    urgency = str(notable.get("urgency") or notable.get("severity") or "medium").lower()
    techniques_raw = notable.get("annotations.mitre_attack") or notable.get("mitre_attack") or []
    if isinstance(techniques_raw, str):
        techniques_raw = [t.strip() for t in techniques_raw.split(",") if t.strip()]
    attacks = [
        Attack(technique=Technique(uid=str(t)))
        for t in techniques_raw
        if str(t).upper().startswith("T")
    ]
    return DetectionFinding(
        time=parse_ts(ev["@timestamp"]),
        metadata=new_metadata("Splunk Enterprise Security", "Splunk", labels=[f"splunk:{name}"]),
        severity_id=_URGENCY.get(urgency, SeverityId.MEDIUM),
        message=str(notable.get("description") or name),
        finding_info=FindingInfo(
            title=name,
            uid=str(ev["event_id"]),
            desc=notable.get("description"),
            analytic=Analytic(name=name, type="Rule", type_id=1),
            attacks=attacks,
        ),
        observables=observables_from_event(ev),
        evidences=[evidence_from_event(ev, raw=ev.get("raw"))],
        device=device_from_event(ev),
        actor=actor_from_event(ev),
        unmapped={"source": "splunk"},
    )
