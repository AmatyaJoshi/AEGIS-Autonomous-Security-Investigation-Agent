"""SOC capability endpoints (SPEC §6 extension): the five modern-SOC pillars.

1. Continuous monitoring   -> ``/api/monitor``    (live posture, activity feed, coverage)
2. Log collection/analysis -> ``/api/logs/*``     (scoped search + facets over the SIEM)
3. Threat detection        -> ``/api/threats``    (IoCs, detections, ATT&CK coverage, TI feed)
4. Incident response       -> ``/api/response``   (playbooks + incidents needing action)
5. Automation              -> ``/api/automation`` (fast-path/auto-close posture + rules)

Everything reads from the offline DuckDB snapshot and the review store. DuckDB
access is serialised behind a lock (the connection is not thread-safe across FastAPI's threadpool).
"""

from __future__ import annotations

import threading
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException, Query

from aegis.api.store import Store
from aegis.config import get_settings

router = APIRouter(prefix="/api")
_store = Store()
_lock = threading.Lock()
_siem: Any = None
_snapshot = "dev"

_SEARCH_COLUMNS = (
    "process_command_line",
    "message",
    "process_name",
    "process_executable",
    "script_block_text",
    "file_path",
    "dns_question_name",
    "user_name",
    "host_name",
)


def _snap_dir() -> Path:
    return get_settings().data.snapshots / _snapshot


def _get_siem() -> Any:
    global _siem
    if _siem is None:
        from aegis.siem.duckdb import DuckDBSiem

        d = _snap_dir()
        if not (d / "events").exists():
            raise HTTPException(503, f"snapshot '{_snapshot}' not built")
        _siem = DuckDBSiem(d)
    return _siem


# ================================================================= 1. Continuous monitoring
@router.get("/monitor")
def monitor() -> dict[str, Any]:
    m = _store.metrics()
    invs = _store.list_investigations(limit=25)
    coverage: dict[str, Any] = {}
    try:
        with _lock:
            coverage = _get_siem().stats()
    except HTTPException:
        coverage = {}
    events_total = sum(v.get("events", 0) for v in coverage.values())
    hosts = sum(v.get("hosts", 0) for v in coverage.values())
    feed = [
        {
            "investigation_id": i["investigation_id"],
            "title": i["title"],
            "verdict": i["verdict"],
            "severity": i["severity"],
            "confidence": i["confidence"],
            "created_at": i["created_at"],
            "injection_flagged": i["injection_flagged"],
        }
        for i in invs
    ]
    return {
        "posture": {
            "total_investigations": m["total"],
            "by_verdict": m["by_verdict"],
            "open_incidents": (
                m["by_verdict"].get("true_positive", 0) + m["by_verdict"].get("escalate", 0)
            ),
            "auto_suppressed": m["by_verdict"].get("false_positive", 0),
            "injection_events": sum(1 for i in invs if i["injection_flagged"]),
            "avg_latency_s": m["avg_seconds"],
        },
        "coverage": {
            "datasets": coverage,
            "events_monitored": events_total,
            "hosts": hosts,
            "snapshot": _snapshot,
        },
        "feed": feed,
        "generated_at": datetime.now(tz=UTC).isoformat(),
    }


# ================================================================= 2. Log collection & analysis
@router.get("/logs/search")
def logs_search(
    q: str = Query("", description="free-text over command line / message / names"),
    host: str = Query(""),
    user: str = Query(""),
    action: str = Query(""),
    dataset: str = Query(""),
    limit: int = Query(100, le=500),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if q:
        ors = " OR ".join(f"lower(CAST({c} AS VARCHAR)) LIKE ?" for c in _SEARCH_COLUMNS)
        clauses.append(f"({ors})")
        params += [f"%{q.lower()}%"] * len(_SEARCH_COLUMNS)
    for col, val in (
        ("host_name", host),
        ("user_name", user),
        ("event_action", action),
        ("dataset", dataset),
    ):
        if val:
            clauses.append(f"{col} = ?")
            params.append(val)
    where = " AND ".join(clauses) if clauses else "TRUE"
    cols = (
        'event_id, "@timestamp", dataset, host_name, user_name, event_action, '
        "event_channel, process_name, process_command_line, source_ip, destination_ip, message"
    )
    with _lock:
        siem = _get_siem()
        rows = (
            siem.con.execute(
                f'SELECT {cols} FROM events WHERE {where} ORDER BY "@timestamp" DESC LIMIT ?',
                [*params, limit],
            )
            .fetchdf()
            .to_dict("records")
        )
        # facets over the same filter (top hosts / actions), bounded
        facet_actions = (
            siem.con.execute(
                f"SELECT event_action AS k, count(*) AS n FROM events WHERE {where} "
                "AND event_action IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 8",
                params,
            )
            .fetchdf()
            .to_dict("records")
        )
        facet_hosts = (
            siem.con.execute(
                f"SELECT host_name AS k, count(*) AS n FROM events WHERE {where} "
                "AND host_name IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 8",
                params,
            )
            .fetchdf()
            .to_dict("records")
        )
    clean = [{k: (None if _isnan(v) else v) for k, v in r.items()} for r in rows]
    return {
        "count": len(clean),
        "rows": clean,
        "facets": {
            "actions": [_kv(r) for r in facet_actions],
            "hosts": [_kv(r) for r in facet_hosts],
        },
    }


@router.get("/logs/stats")
def logs_stats() -> dict[str, Any]:
    with _lock:
        stats = _get_siem().stats()
    return {"datasets": stats, "total": sum(v.get("events", 0) for v in stats.values())}


# ================================================================= 3. Threat detection
@router.get("/threats")
def threats() -> dict[str, Any]:
    from aegis.intel.providers.offline import KNOWN_BAD_DOMAINS, KNOWN_BAD_HASHES, KNOWN_BAD_IPS

    invs = _store.list_investigations(limit=500)
    detections = [
        {
            "investigation_id": i["investigation_id"],
            "title": i["title"],
            "techniques": i["techniques"],
            "severity": i["severity"],
            "confidence": i["confidence"],
            "verdict": i["verdict"],
            "created_at": i["created_at"],
        }
        for i in invs
        if i["verdict"] in ("true_positive", "escalate")
    ]
    tech_hist = Counter(t for i in invs for t in (i["techniques"] or []))
    ioc: list[dict[str, Any]] = []
    for d, (score, cats) in KNOWN_BAD_DOMAINS.items():
        ioc.append({"indicator": d, "type": "domain", "score": score, "categories": cats})
    for ip, (score, cats) in KNOWN_BAD_IPS.items():
        ioc.append({"indicator": ip, "type": "ip", "score": score, "categories": cats})
    for h, (score, cats) in KNOWN_BAD_HASHES.items():
        ioc.append({"indicator": h, "type": "hash", "score": score, "categories": cats})
    ioc.sort(key=lambda x: -x["score"])
    return {
        "detections": detections[:50],
        "detection_count": len(detections),
        "top_techniques": [
            {"technique": t, "count": n, "name": _tech_name(t)}
            for t, n in tech_hist.most_common(12)
        ],
        "iocs": ioc,
        "intel_feed_size": len(ioc),
    }


# ================================================================= 4. Incident response
@router.get("/response")
def response() -> dict[str, Any]:
    playbooks = _load_playbooks()
    invs = _store.list_investigations(limit=200)
    from aegis.graph.playbooks import select_playbook

    incidents = []
    for i in invs:
        if i["verdict"] not in ("true_positive", "escalate"):
            continue
        pb = select_playbook(i["verdict"], i["techniques"], i["severity"] or "medium")
        incidents.append(
            {
                "investigation_id": i["investigation_id"],
                "title": i["title"],
                "verdict": i["verdict"],
                "severity": i["severity"],
                "techniques": i["techniques"],
                "playbook": pb["name"] if pb else None,
                "playbook_id": pb["id"] if pb else None,
                "created_at": i["created_at"],
            }
        )
    return {"playbooks": playbooks, "incidents": incidents, "open_count": len(incidents)}


# ================================================================= 5. Automation
@router.get("/automation")
def automation() -> dict[str, Any]:
    m = _store.metrics()
    total = m["total"] or 1
    auto = m["by_verdict"].get("false_positive", 0)  # auto-suppressed FPs
    manual = m["reviews"]
    # rough analyst-time saved: assume ~8 min manual triage per alert AEGIS handled autonomously
    minutes_saved = round((total - manual) * 8, 0)
    return {
        "kpis": {
            "auto_triaged_rate": round((total - manual) / total, 4),
            "fast_path_rate": m["fast_path_rate"],
            "auto_suppressed": auto,
            "avg_latency_s": m["avg_seconds"],
            "avg_cost_usd": m["avg_cost_usd"],
            "analyst_minutes_saved": minutes_saved,
            "manual_reviews": manual,
            "total": m["total"],
        },
        "rules": [
            {
                "name": "Fast-path FP suppression",
                "trigger": "triage model p(FP) > 0.97 and low severity",
                "action": "auto-close as false positive (still logged & reviewable)",
                "enabled": True,
                "kind": "suppression",
            },
            {
                "name": "Prompt-injection guard",
                "trigger": "injection detected in log content",
                "action": "force escalate to human",
                "enabled": True,
                "kind": "safety",
            },
            {
                "name": "Budget guard",
                "trigger": "tool/LLM/time budget exceeded",
                "action": "escalate with partial results",
                "enabled": True,
                "kind": "safety",
            },
            {
                "name": "Evidence-cited reporting",
                "trigger": "every verdict",
                "action": "generate a report where each claim cites a real event",
                "enabled": True,
                "kind": "quality",
            },
        ],
        "guardrails": [
            "Recommend-only: no containment is executed automatically",
            "Read-only SIEM access",
            "Full audit trail per verdict",
        ],
    }


# ================================================================= Assets & Identities (CMDB/IdP)
@router.get("/assets")
def assets() -> dict[str, Any]:
    org = _org()
    return {
        "hosts": org.get("hosts", []),
        "count": len(org.get("hosts", [])),
        "domain": org.get("domain"),
        "zones": sorted({h.get("zone") for h in org.get("hosts", []) if h.get("zone")}),
    }


@router.get("/identities")
def identities() -> dict[str, Any]:
    org = _org()
    users = org.get("users", [])
    return {
        "users": users,
        "count": len(users),
        "privileged": sum(1 for u in users if u.get("privileged")),
        "service_accounts": sum(1 for u in users if u.get("service")),
    }


def _org() -> dict[str, Any]:
    path = Path(__file__).resolve().parent.parent.parent / "lab" / "noise" / "org.yaml"
    doc: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return doc


# ------------------------------------------------------------------ helpers
def _load_playbooks() -> list[dict[str, Any]]:
    d = Path(__file__).resolve().parent.parent / "playbooks"
    out: list[dict[str, Any]] = []
    for p in sorted(d.glob("*.yaml")):
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        if isinstance(doc, dict):
            out.append(
                {
                    "id": doc.get("id"),
                    "name": doc.get("name"),
                    "techniques": doc.get("techniques", []),
                    "verdicts": doc.get("applies_when", {}).get("verdict", []),
                    "steps": [
                        {
                            "action": s.get("action"),
                            "owner": s.get("owner"),
                            "requires_approval": bool(s.get("requires_approval")),
                        }
                        for s in doc.get("recommended_steps", [])
                    ],
                }
            )
    return out


def _tech_name(tid: str) -> str:
    try:
        from aegis.attack.kb import load_kb

        t = load_kb().get(tid)
        return t.name if t else tid
    except Exception:
        return tid


def _kv(r: dict[str, Any]) -> dict[str, Any]:
    return {"key": r.get("k"), "count": int(r.get("n", 0))}


def _isnan(v: Any) -> bool:
    return isinstance(v, float) and v != v
