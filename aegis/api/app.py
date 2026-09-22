"""FastAPI review backend (SPEC §6): queue, investigation detail, labels, metrics, live WebSocket.

Endpoints
---------
* ``GET  /api/queue``                    - investigation summaries (verdict, confidence, ...).
* ``GET  /api/investigations/{id}``      - full investigation (report, hypotheses, timeline, alert).
* ``POST /api/investigations/{id}/review`` - approve / override / annotate (override -> gold label).
* ``GET  /api/metrics``                  - live FP-suppression, fast-path rate, cost/alert, accura
* ``POST /api/investigate``              - run N alerts from the snapshot into the queue (demo/liv
* ``WS   /ws``                           - broadcast of new investigations as they complete.
* ``GET  /health``.

The Next.js UI (``web/``) consumes this API. Offline it is SQLite-backed; no server needed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aegis.api.store import Store

app = FastAPI(title="AEGIS Review API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
_store = Store()

from aegis.api.assistant import router as assistant_router  # noqa: E402
from aegis.api.auth import require_role, seed_demo_users  # noqa: E402
from aegis.api.auth import router as auth_router  # noqa: E402
from aegis.api.soc import router as soc_router  # noqa: E402

app.include_router(auth_router)
app.include_router(soc_router)
app.include_router(assistant_router)
seed_demo_users()  # idempotent: ensures the console has demo accounts on first load

from aegis.llm.budget import log_allowlist  # noqa: E402

log_allowlist()  # COST.md: one startup line listing every outbound host


class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        for ws in list(self.clients):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws)


hub = Hub()


class ReviewIn(BaseModel):
    analyst: str
    action: str  # approve | override | annotate
    override_verdict: str | None = None
    annotation: str | None = None


class InvestigateIn(BaseModel):
    snapshot: str = "dev"
    limit: int = 10
    seed: int = 1337


_router: Any = None
_memory: Any = None


def get_memory() -> Any:
    """Process-wide case memory (Phase 1): Pulse mirror when configured, else local SQLite."""
    global _memory
    if _memory is None:
        from aegis.memory.store import open_memory

        _memory = open_memory()
    return _memory


def get_router() -> Any:
    """Process-wide LLM router (provider resolution is cached; Ollama probe happens once)."""
    global _router
    if _router is None:
        from aegis.llm.router import LLMRouter

        _router = LLMRouter()
    return _router


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness + cost posture (COST.md): ``cost_mode`` is ``normal`` or ``degraded``."""
    from aegis.llm.budget import get_guard

    r = get_router()
    d = r.describe()
    mem = get_memory().status()
    return {
        "status": "ok",
        "cost_mode": d["cost_mode"],
        "degraded_reason": d["degraded_reason"],
        "llm": {"provider": d["provider"] or "none", "model": d["model"]},
        "memory": {"backend": mem["backend"], "priors_source": mem["priors_source"]},
        "budget": get_guard().snapshot(),
    }


@app.get("/api/memory")
def memory_panel() -> dict[str, Any]:
    """Memory panel (Phase 1): priors by technique, analyst-override rate, source, analytics."""
    mem = get_memory()
    priors = mem.priors()
    techniques = sorted(
        (p for k, p in priors.items() if not k.startswith("source:")),
        key=lambda p: (p.n, p.tp_rate),
        reverse=True,
    )
    sources = [p for k, p in priors.items() if k.startswith("source:")]
    reviewed = [p for p in priors.values() if p.analyst_override_rate or p.n]
    override = (
        round(sum(p.analyst_override_rate * p.n for p in reviewed) / sum(p.n for p in reviewed), 4)
        if reviewed and sum(p.n for p in reviewed)
        else 0.0
    )
    status = mem.status()
    return {
        "backend": status["backend"],
        "priors_source": status["priors_source"],
        "cases": status.get("cases", 0),
        "feedback": status.get("feedback", 0),
        "pulse_calls": status.get("pulse_calls"),
        "pulse_calls_per_day": status.get("pulse_calls_per_day"),
        "last_error": status.get("last_error"),
        "analyst_override_rate": override,
        "techniques": [p.to_row() for p in techniques[:12]],
        "sources": [p.to_row() for p in sources],
        "analytics": mem.analytics(),
    }


@app.get("/api/queue")
def queue(verdict: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    return _store.list_investigations(verdict=verdict, limit=limit)


@app.get("/api/investigations/{investigation_id}")
def investigation(investigation_id: str) -> dict[str, Any]:
    inv = _store.get_investigation(investigation_id)
    if inv is None:
        raise HTTPException(404, "investigation not found")
    return inv


@app.post("/api/investigations/{investigation_id}/review")
def review(
    investigation_id: str,
    body: ReviewIn,
    user: dict[str, Any] = Depends(require_role("analyst")),
) -> dict[str, Any]:
    try:
        rid = _store.add_review(
            investigation_id, user["name"], body.action, body.override_verdict, body.annotation
        )
    except KeyError as e:
        raise HTTPException(404, "investigation not found") from e
    _remember_feedback(investigation_id, body)
    return {"review_id": rid, "status": "recorded"}


def _remember_feedback(investigation_id: str, body: ReviewIn) -> None:
    """Analyst decision -> case memory (metadata only: case id, verdict, agreed, reason code)."""
    if body.action not in ("approve", "override"):
        return
    inv = _store.get_investigation(investigation_id)
    if inv is None:
        return
    from aegis.memory.store import FeedbackRecord

    aegis_verdict = str(inv.get("verdict") or "")
    analyst_verdict = body.override_verdict if body.action == "override" else aegis_verdict
    try:
        mem = get_memory()
        mem.record_feedback(
            FeedbackRecord(
                case_id=investigation_id,
                analyst_verdict=analyst_verdict or aegis_verdict,
                agreed=(analyst_verdict or aegis_verdict) == aegis_verdict,
                reason_code=body.action,
            )
        )
        if hasattr(mem, "flush_priors"):
            mem.flush_priors()
    except Exception:  # memory must never break the review
        pass


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    return _store.metrics()


@app.post("/api/investigate")
async def investigate(
    body: InvestigateIn, user: dict[str, Any] = Depends(require_role("analyst"))
) -> dict[str, Any]:
    from aegis.config import get_settings

    settings = get_settings()
    snap = settings.data.snapshots / body.snapshot
    if not snap.exists():
        raise HTTPException(400, f"snapshot {body.snapshot} not found")
    count = await asyncio.to_thread(_run_batch, snap, body.limit, body.seed)
    return {"investigated": count}


def _run_batch(snap: Path, limit: int, seed: int) -> int:
    from aegis.graph.deps import Deps
    from aegis.graph.reasoner import HeuristicReasoner
    from aegis.graph.runner import run_investigation
    from aegis.ingest.generate import generate_alerts
    from aegis.siem.duckdb import DuckDBSiem

    siem = DuckDBSiem(snap)
    reasoner: Any = HeuristicReasoner()
    router = get_router()
    if router.available:
        from aegis.graph.llm_reasoner import LLMReasoner

        reasoner = LLMReasoner(router)
    mem = get_memory()
    deps = Deps(
        siem=siem,
        reasoner=reasoner,
        pack_path=str(snap / "rules" / "sigma_pack.jsonl"),
        memory=mem,
        triage=_load_default_triage(),
    )
    n = 0
    try:
        for rec in generate_alerts(snap, pack_path=snap / "rules" / "sigma_pack.jsonl", seed=seed):
            res = run_investigation(rec.alert, deps)
            _store.save_result(
                res, gold_label=rec.gold_label, dataset=rec.dataset, fp_type=rec.fp_type
            )
            n += 1
            if n >= limit:
                break
    finally:
        siem.close()
        if hasattr(mem, "flush_priors"):
            mem.flush_priors()  # one batched priors write per run (free-tier budget)
    return n


def _load_default_triage() -> Any:
    """Use the trained LightGBM model when its artefact exists (priors need a p_tp to blend)."""
    import os

    p = Path(os.environ.get("AEGIS_TRIAGE_MODEL", "training/triage/artifacts/model.txt"))
    if not p.exists():
        return None
    try:
        from aegis.models.triage import load_triage

        return load_triage(p)
    except Exception:
        return None


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(ws)


def get_store() -> Store:
    return _store
