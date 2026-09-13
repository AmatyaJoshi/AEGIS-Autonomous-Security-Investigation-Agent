"""Execution-based evaluation of the NL->query generator (SPEC §7.2) - NOT string match.

For each eval case (an investigative intent + entities + window + a hand-authored gold query),
we run the *generated* query and the *gold* query against the snapshot and compare the returned
``event_id`` sets:

* **exact equivalence** - identical event-id sets;
* **lenient equivalence** - Jaccard(generated, gold) >= 0.9;

plus syntactic validity, validator rejection rate, latency, and a per-category breakdown. Gold
queries are authored independently of the generator (different columns/predicate spelling) so the
metric measures whether the generated query returns the same rows, not the same SQL text.

The offline default evaluates the deterministic ``QueryGenerator`` (template backend). A fine-tuned
model or a frontier zero-shot baseline can be plugged in behind the same generate API for a
head-to-head table.

    python -m training.query_gen.eval_exec --snapshot dev
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aegis.models.query_gen import QueryGenerator
from aegis.siem.base import TimeWindow
from aegis.siem.duckdb import DuckDBSiem
from aegis.siem.validator import validate_sql

RESULTS = Path("training") / "results"
_KNOWN_HOSTS = {
    "DC01",
    "WS-DEV1",
    "WS-DEV2",
    "WS-ALICE",
    "WS-BOB",
    "FS01",
    "SQL01",
    "BACKUP01",
    "SCCM01",
    "WEB01",
    "WS-HELPDESK",
    "SCAN01",
    "BUILD01",
    "WS-CAROL",
}

# Full-history window covering the snapshot (benign noise spans ~2025-01..2025-04).
WIN = TimeWindow(start=datetime(2024, 12, 1, tzinfo=UTC), end=datetime(2025, 12, 31, tzinfo=UTC))


@dataclass
class EvalCase:
    intent: str
    entities: list[str]
    category: str
    gold_sql: str  # DuckDB; must SELECT event_id and be time+entity scoped


def _gold(where: str) -> str:
    lo = WIN.start.strftime("%Y-%m-%d %H:%M:%S")
    hi = WIN.end.strftime("%Y-%m-%d %H:%M:%S")
    return (
        f"SELECT event_id FROM events WHERE \"@timestamp\" BETWEEN TIMESTAMP '{lo}' "
        f"AND TIMESTAMP '{hi}' AND {where} LIMIT 500"
    )


def eval_cases() -> list[EvalCase]:
    return [
        EvalCase(
            "show all process creations by svc_backup on BACKUP01",
            ["BACKUP01", "svc_backup"],
            "process",
            _gold(
                "host_name='BACKUP01' AND user_name='svc_backup' AND event_action='process_created'"
            ),
        ),
        EvalCase(
            "list process executions by svc_sccm on SCCM01",
            ["SCCM01", "svc_sccm"],
            "process",
            _gold("host_name='SCCM01' AND user_name='svc_sccm' AND event_action='process_created'"),
        ),
        EvalCase(
            "find network connections from BACKUP01",
            ["BACKUP01"],
            "network",
            _gold("host_name='BACKUP01' AND event_action='network_connection'"),
        ),
        EvalCase(
            "show logons for svc_backup on FS01",
            ["FS01", "svc_backup"],
            "logon",
            _gold(
                "host_name='FS01' AND (user_name='svc_backup' "
                "OR user_target_name='svc_backup') AND event_category='authentication'"
            ),
        ),
        EvalCase(
            "show powershell script block activity on DC01",
            ["DC01"],
            "powershell",
            _gold("host_name='DC01' AND event_action IN ('script_block_logged','module_logged')"),
        ),
        EvalCase(
            "find file writes on SCCM01",
            ["SCCM01"],
            "file",
            _gold("host_name='SCCM01' AND event_category='file'"),
        ),
        EvalCase(
            "show services installed on FS01",
            ["FS01"],
            "service",
            _gold("host_name='FS01' AND event_action='service_installed'"),
        ),
        EvalCase(
            "list all process creations by dev.kumar on WS-DEV1",
            ["WS-DEV1", "dev.kumar"],
            "process",
            _gold(
                "host_name='WS-DEV1' AND user_name='dev.kumar' AND event_action='process_created'"
            ),
        ),
        EvalCase(
            "show process activity by adm.patel",
            ["adm.patel"],
            "process",
            _gold("user_name='adm.patel' AND event_action='process_created'"),
        ),
        EvalCase(
            "find registry modifications on SQL01",
            ["SQL01"],
            "registry",
            _gold("host_name='SQL01' AND event_category='registry'"),
        ),
    ]


@dataclass
class CaseResult:
    intent: str
    category: str
    generated_query: str
    valid: bool
    validator_ok: bool
    exact: bool
    jaccard: float
    gen_rows: int
    gold_rows: int
    latency_ms: float
    error: str | None = None


def _ids(siem: DuckDBSiem, sql: str) -> set[str]:
    res = siem.con.execute(sql).fetchdf()
    return set(res["event_id"].astype(str).tolist()) if "event_id" in res.columns else set()


def evaluate(
    snapshot_dir: Path, generator: QueryGenerator | None = None, backend_name: str = "template"
) -> dict[str, Any]:
    generator = generator or QueryGenerator(known_hosts=_KNOWN_HOSTS)
    siem = DuckDBSiem(snapshot_dir)
    results: list[CaseResult] = []
    try:
        for case in eval_cases():
            t0 = time.perf_counter()
            gen = generator.generate(case.intent, case.entities, WIN, dialect="duckdb", limit=500)
            latency = (time.perf_counter() - t0) * 1000
            validator_ok = gen.validation.ok
            error = None
            gen_ids: set[str] = set()
            valid = True
            try:
                gen_ids = _ids(siem, gen.query)
            except Exception as e:
                valid = False
                error = f"{type(e).__name__}: {e}"[:150]
            gold_ids = _ids(siem, case.gold_sql)
            inter = len(gen_ids & gold_ids)
            union = len(gen_ids | gold_ids)
            jac = 1.0 if (union == 0 and valid) else (inter / union if union else 0.0)
            results.append(
                CaseResult(
                    intent=case.intent,
                    category=case.category,
                    generated_query=gen.query,
                    valid=valid,
                    validator_ok=validator_ok,
                    exact=(gen_ids == gold_ids and valid),
                    jaccard=round(jac, 4),
                    gen_rows=len(gen_ids),
                    gold_rows=len(gold_ids),
                    latency_ms=round(latency, 3),
                    error=error,
                )
            )
    finally:
        siem.close()

    n = len(results)
    exact = sum(r.exact for r in results)
    lenient = sum(1 for r in results if r.jaccard >= 0.9 and r.valid)
    from collections import defaultdict

    per_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "exact": 0})
    for r in results:
        per_cat[r.category]["n"] += 1
        per_cat[r.category]["exact"] += int(r.exact)
    summary = {
        "backend": backend_name,
        "n_cases": n,
        "exact_equivalence": round(exact / n, 4) if n else 0.0,
        "lenient_equivalence_j0.9": round(lenient / n, 4) if n else 0.0,
        "syntactic_validity": round(sum(r.valid for r in results) / n, 4) if n else 0.0,
        "validator_pass_rate": round(sum(r.validator_ok for r in results) / n, 4) if n else 0.0,
        "avg_latency_ms": round(sum(r.latency_ms for r in results) / n, 3) if n else 0.0,
        "per_category": {
            k: {**v, "exact_rate": round(v["exact"] / v["n"], 3)}
            for k, v in sorted(per_cat.items())
        },
        "cases": [r.__dict__ for r in results],
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = f"{datetime.now(tz=UTC).strftime('%Y%m%d')}_{_git_sha()}_querygen"
    (RESULTS / f"{stamp}.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    return summary


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "nogit"


_ = re, timedelta, validate_sql  # kept for future dialect/latency extensions


if __name__ == "__main__":
    import argparse

    from aegis.config import get_settings

    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", default="dev")
    args = ap.parse_args()
    s = get_settings()
    print(json.dumps(evaluate(s.data.snapshots / args.snapshot), indent=1))
