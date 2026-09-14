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

from aegis.api.auth import require_role, seed_demo_users  # noqa: E402
from aegis.api.auth import router as auth_router  # noqa: E402
from aegis.api.soc import router as soc_router  # noqa: E402

app.include_router(auth_router)
app.include_router(soc_router)
seed_demo_users()  # idempotent: ensures the console has demo accounts on first load


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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


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
    return {"review_id": rid, "status": "recorded"}


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
    deps = Deps(
        siem=siem, reasoner=HeuristicReasoner(), pack_path=str(snap / "rules" / "sigma_pack.jsonl")
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
    return n


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
