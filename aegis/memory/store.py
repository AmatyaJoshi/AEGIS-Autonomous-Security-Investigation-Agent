"""Case memory: what AEGIS learned from every investigation, fed back into ``triage_pre``.

Two backends behind one interface (``MemoryStore``):

* :class:`LocalStore` - SQLite under ``data/memory.db``. Always present, always written. Priors are
  recomputed from the local case + feedback rows.
* :class:`PulseStore` - mirrors the same rows to Evorozen Neural Pulse (hosted "Neural DB") and
  reads priors back from its ``aegis_priors`` table; one cached ``analytics`` answer per day.

:func:`open_memory` builds the composite: with ``AEGIS_MEMORY_BACKEND=auto`` (default) it writes
locally and mirrors to Pulse when the key is set and Pulse answers within 2 s; otherwise the same
interface runs local-only and reports ``backend == "local"`` so the UI can say "memory: local".

**Hard boundary (SECURITY.md).** Pulse receives *metadata only*: technique ids, alert source,
severity, verdict, confidence, counts, durations, a salted hash of the tenant id and model / prompt
versions. Never raw events, hostnames, usernames, IPs, alert text or report bodies.
:func:`CaseRecord.from_result` is the only place a record is built from an investigation, and
``tests/test_memory.py`` asserts that nothing identifying survives serialisation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

from aegis.memory.priors import Prior, compute_priors
from aegis.memory.pulse_client import PulseClient, PulseUnavailableError

if TYPE_CHECKING:
    from aegis.graph.runner import InvestigationResult

log = logging.getLogger("aegis.memory")

Backend = Literal["pulse", "local"]
ANALYTICS_QUESTION = "Which techniques most often end as false positives this month?"

# Schema registered on first use (idempotent). Pulse column types follow its docs (uuid/text/...).
TABLES: list[dict[str, Any]] = [
    {
        "name": "aegis_cases",
        "columns": [
            {"name": "case_id", "type": "text", "primary": True},
            {"name": "tenant_hash", "type": "text"},
            {"name": "attack_technique_ids", "type": "json"},
            {"name": "alert_source", "type": "text"},
            {"name": "severity_in", "type": "text"},
            {"name": "verdict", "type": "text"},
            {"name": "confidence", "type": "float"},
            {"name": "escalated", "type": "boolean"},
            {"name": "triage_p_tp", "type": "float"},
            {"name": "reasoner", "type": "text"},
            {"name": "model", "type": "text"},
            {"name": "prompt_version", "type": "text"},
            {"name": "n_hypotheses", "type": "integer"},
            {"name": "n_queries", "type": "integer"},
            {"name": "evidence_count", "type": "integer"},
            {"name": "duration_s", "type": "float"},
            {"name": "cost_usd", "type": "float"},
            {"name": "created_at", "type": "text"},
        ],
    },
    {
        "name": "aegis_feedback",
        "columns": [
            {"name": "case_id", "type": "text", "primary": True},
            {"name": "analyst_verdict", "type": "text"},
            {"name": "agreed", "type": "boolean"},
            {"name": "reason_code", "type": "text"},
            {"name": "created_at", "type": "text"},
        ],
    },
    {
        "name": "aegis_priors",
        "columns": [
            {"name": "key", "type": "text", "primary": True},
            {"name": "n", "type": "integer"},
            {"name": "tp_rate", "type": "float"},
            {"name": "escalate_rate", "type": "float"},
            {"name": "analyst_override_rate", "type": "float"},
            {"name": "updated_at", "type": "text"},
        ],
    },
]

# Field names that must never appear in anything sent to Pulse.
FORBIDDEN_FIELDS = (
    "host",
    "hostname",
    "host_name",
    "user",
    "user_name",
    "username",
    "ip",
    "src_ip",
    "dst_ip",
    "title",
    "message",
    "command_line",
    "cmd_line",
    "report",
    "report_md",
    "raw",
)


def tenant_hash(tenant: str | None = None) -> str:
    """Salted, truncated SHA-256 of the tenant id (``AEGIS_TENANT``, default ``lab``)."""
    tenant = tenant or os.environ.get("AEGIS_TENANT", "lab")
    salt = os.environ.get("AEGIS_TENANT_SALT", "aegis")
    return hashlib.sha256(f"{salt}:{tenant}".encode()).hexdigest()[:16]


@dataclass
class CaseRecord:
    case_id: str
    tenant_hash: str
    attack_technique_ids: list[str]
    alert_source: str
    severity_in: str
    verdict: str
    confidence: float
    escalated: bool
    triage_p_tp: float | None
    reasoner: str
    model: str | None
    prompt_version: str
    n_hypotheses: int
    n_queries: int
    evidence_count: int
    duration_s: float
    cost_usd: float
    created_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        assert not (set(row) & set(FORBIDDEN_FIELDS)), "metadata-only boundary violated"
        return row

    @classmethod
    def from_result(
        cls,
        result: InvestigationResult,
        *,
        reasoner: str,
        model: str | None,
        source: str = "offline",
        tenant: str | None = None,
    ) -> CaseRecord:
        v = result.verdict
        alert = result.alert
        tech = sorted({t for t in (v.techniques if v else []) if t} | set(alert.technique_ids))
        evidence = sum(len(h.evidence_for) + len(h.evidence_against) for h in result.hypotheses)
        return cls(
            case_id=result.investigation_id,
            tenant_hash=tenant_hash(tenant),
            attack_technique_ids=tech,
            alert_source=source,
            severity_in=str(alert.severity or alert.severity_id.name).lower(),
            verdict=v.label if v else "unknown",
            confidence=round(float(v.confidence), 4) if v else 0.0,
            escalated=bool(v and v.label == "escalate"),
            triage_p_tp=round(float(v.triage_model_score), 4)
            if v and v.triage_model_score is not None
            else None,
            reasoner=reasoner,
            model=model,
            prompt_version=",".join(f"{k}={n}" for k, n in sorted(result.prompt_versions.items())),
            n_hypotheses=len(result.hypotheses),
            n_queries=int(result.spent.tool_calls),
            evidence_count=evidence,
            duration_s=round(float(result.seconds), 3),
            cost_usd=round(float(result.spent.cost_usd), 6),
        )


@dataclass
class FeedbackRecord:
    case_id: str
    analyst_verdict: str
    agreed: bool
    reason_code: str
    created_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


class MemoryStore(Protocol):
    backend: str

    def record_case(self, case: CaseRecord) -> None: ...
    def record_feedback(self, fb: FeedbackRecord) -> None: ...
    def priors(self) -> dict[str, Prior]: ...
    def analytics(self, question: str = ANALYTICS_QUESTION) -> dict[str, Any]: ...
    def status(self) -> dict[str, Any]: ...


# ================================================================== local (SQLite)
class LocalStore:
    backend = "local"

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(os.environ.get("AEGIS_DATA_ROOT", "data")) / "memory.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        with self._conn() as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS aegis_cases "
                "(case_id TEXT PRIMARY KEY, row TEXT NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS aegis_feedback "
                "(case_id TEXT PRIMARY KEY, row TEXT NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS aegis_analytics "
                "(question TEXT PRIMARY KEY, answer TEXT, source TEXT, cached_at TEXT)"
            )

    def record_case(self, case: CaseRecord) -> None:
        with self._conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO aegis_cases VALUES (?, ?)",
                (case.case_id, json.dumps(case.to_row())),
            )

    def record_feedback(self, fb: FeedbackRecord) -> None:
        with self._conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO aegis_feedback VALUES (?, ?)",
                (fb.case_id, json.dumps(fb.to_row())),
            )

    def cases(self) -> list[dict[str, Any]]:
        with self._conn() as con:
            return [json.loads(r["row"]) for r in con.execute("SELECT row FROM aegis_cases")]

    def feedback(self) -> list[dict[str, Any]]:
        with self._conn() as con:
            return [json.loads(r["row"]) for r in con.execute("SELECT row FROM aegis_feedback")]

    def priors(self) -> dict[str, Prior]:
        return compute_priors(self.cases(), self.feedback())

    def analytics(self, question: str = ANALYTICS_QUESTION) -> dict[str, Any]:
        """Deterministic local answer: FP rate by technique over the last 30 days."""
        cutoff = time.time() - 30 * 86400
        by: dict[str, list[int]] = {}
        for c in self.cases():
            try:
                ts = datetime.fromisoformat(c["created_at"]).timestamp()
            except (KeyError, ValueError):
                ts = time.time()
            if ts < cutoff:
                continue
            for t in c.get("attack_technique_ids") or []:
                by.setdefault(t, [0, 0])
                by[t][0] += 1
                by[t][1] += c.get("verdict") == "false_positive"
        ranked = sorted(by.items(), key=lambda kv: (kv[1][1] / kv[1][0], kv[1][0]), reverse=True)
        top = [f"{t}: {fp}/{n} FP" for t, (n, fp) in ranked[:5] if fp]
        answer = (
            "Most frequent false-positive techniques (last 30 days): " + "; ".join(top)
            if top
            else "No false positives recorded in the last 30 days."
        )
        return {
            "question": question,
            "answer": answer,
            "source": "local",
            "cached_at": datetime.now(tz=UTC).isoformat(),
        }

    def status(self) -> dict[str, Any]:
        return {
            "backend": "local",
            "priors_source": "local",
            "cases": len(self.cases()),
            "feedback": len(self.feedback()),
            "path": str(self.path),
        }


# ================================================================== Pulse mirror
class PulseStore:
    """Writes the same rows to Pulse; reads priors from Pulse (cached); one analytics answer/day."""

    backend = "pulse"

    def __init__(
        self, client: PulseClient, local: LocalStore, *, priors_ttl_s: float = 600.0
    ) -> None:
        self.client = client
        self.local = local
        self.priors_ttl_s = priors_ttl_s
        self._priors_cache: tuple[float, dict[str, Prior]] | None = None
        self._analytics_cache: dict[str, Any] | None = None
        self._schema_marker = local.path.with_suffix(".pulse_schema.json")
        self.last_error: str | None = None
        self.pending_prior_keys: set[str] = set()

    # ---------------------------------------------------------------- schema (idempotent)
    def ensure_schema(self) -> bool:
        """Call ``create_schema`` once per (base_url, schema hash); remember it on disk."""
        digest = hashlib.sha256(json.dumps(TABLES, sort_keys=True).encode()).hexdigest()[:16]
        marker = {"base_url": self.client.base_url, "schema": digest}
        try:
            if json.loads(self._schema_marker.read_text(encoding="utf-8")) == marker:
                return False
        except (OSError, ValueError):
            pass
        self.client.create_schema(TABLES)
        self._schema_marker.write_text(json.dumps(marker), encoding="utf-8")
        return True

    # ---------------------------------------------------------------- writes
    def record_case(self, case: CaseRecord) -> None:
        self.local.record_case(case)
        try:
            self.ensure_schema()
            self.client.insert("aegis_cases", case.to_row())
            self.pending_prior_keys.update(case.attack_technique_ids)
            self.pending_prior_keys.add(f"source:{case.alert_source}")
        except PulseUnavailableError as e:
            self.last_error = str(e)
            log.warning("Pulse write skipped (local copy kept): %s", e)

    def record_feedback(self, fb: FeedbackRecord) -> None:
        self.local.record_feedback(fb)
        try:
            self.ensure_schema()
            self.client.upsert("aegis_feedback", "case_id", fb.to_row())
            case = next((c for c in self.local.cases() if c["case_id"] == fb.case_id), None)
            if case:
                self.pending_prior_keys.update(case.get("attack_technique_ids") or [])
                self.pending_prior_keys.add(f"source:{case.get('alert_source')}")
        except PulseUnavailableError as e:
            self.last_error = str(e)
            log.warning("Pulse feedback skipped (local copy kept): %s", e)

    def flush_priors(self) -> int:
        """Recompute priors locally and upsert only the keys touched since the last flush.

        Called once per investigation batch (not per case) to stay inside the free tier.
        """
        if not self.pending_prior_keys:
            return 0
        fresh = self.local.priors()
        n = 0
        try:
            self.ensure_schema()
            for key in sorted(self.pending_prior_keys):
                if key in fresh:
                    self.client.upsert("aegis_priors", "key", fresh[key].to_row())
                    n += 1
            self.pending_prior_keys.clear()
            self._priors_cache = None
        except PulseUnavailableError as e:
            self.last_error = str(e)
            log.warning("Pulse priors flush interrupted after %d keys: %s", n, e)
        return n

    # ---------------------------------------------------------------- reads
    def priors(self) -> dict[str, Prior]:
        now = time.monotonic()
        if self._priors_cache and now - self._priors_cache[0] < self.priors_ttl_s:
            return self._priors_cache[1]
        try:
            rows = self.client.select("aegis_priors")
            out = {str(r["key"]): Prior.from_row(r) for r in rows if r.get("key")}
            self._priors_cache = (now, out)
            self.last_error = None
            return out
        except PulseUnavailableError as e:
            self.last_error = str(e)
            log.warning("Pulse priors unavailable, using local: %s", e)
            return self.local.priors()

    @property
    def priors_source(self) -> str:
        return "local" if self.last_error else "pulse"

    def analytics(self, question: str = ANALYTICS_QUESTION) -> dict[str, Any]:
        today = datetime.now(tz=UTC).date().isoformat()
        c = self._analytics_cache
        if c and c.get("question") == question and str(c.get("cached_at", "")).startswith(today):
            return c
        try:
            self.ensure_schema()
            answer = self.client.analytics(question, "aegis_cases")
            self._analytics_cache = {
                "question": question,
                "answer": answer or "(empty answer)",
                "source": "pulse",
                "cached_at": datetime.now(tz=UTC).isoformat(),
            }
            return self._analytics_cache
        except PulseUnavailableError as e:
            self.last_error = str(e)
            return self.local.analytics(question)

    def status(self) -> dict[str, Any]:
        s = self.local.status()
        s.update(
            {
                "backend": "pulse",
                "priors_source": self.priors_source,
                "pulse_base_url": self.client.base_url,
                "pulse_calls": self.client.calls,
                "pulse_calls_per_day": self.client.calls_per_day,
                "last_error": self.last_error,
            }
        )
        return s


# ================================================================== factory
def open_memory(
    backend: str | None = None,
    *,
    client: PulseClient | None = None,
    local_path: Path | None = None,
) -> LocalStore | PulseStore:
    """Build the configured store. ``auto`` = Pulse when a key is set and it answers, else local."""
    want = (backend or os.environ.get("AEGIS_MEMORY_BACKEND", "auto")).lower()
    local = LocalStore(local_path)
    if want == "local":
        return local
    client = client or PulseClient()
    if not client.configured:
        if want == "pulse":
            log.warning("AEGIS_MEMORY_BACKEND=pulse but AEGIS_PULSE_API_KEY unset; using local")
        return local
    store = PulseStore(client, local)
    try:
        store.ensure_schema()  # first contact; bounded by timeout_s * (retries + 1)
    except PulseUnavailableError as e:
        if want == "pulse":
            log.warning("Pulse requested but unreachable (%s); memory: local", e)
            return local
        store.last_error = str(e)
    return store
