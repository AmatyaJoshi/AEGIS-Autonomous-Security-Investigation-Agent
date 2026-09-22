"""`aegis demo` - the three-minute live demo, end to end (Phase 2).

1. reset the review queue and case memory (never the datasets or the snapshot);
2. pick five alerts from the frozen benchmark's test split: 1 true positive, 3 false positives of
   different fp_types, 1 ambiguous (gold ``escalate``);
3. investigate them with the configured reasoner (Ollama / Groq / Gemini when reachable, else the
   deterministic reasoner - the UI badge says which) and the triage model when trained;
4. save every investigation to the review store so the UI shows them, remember each case, flush
   priors once, and print the URL of the ambiguous case to open in the review UI.

Everything here is recommend-only and offline except the optional LLM and Pulse calls, both of which
are budget-guarded (COST.md).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.schema.ocsf import DetectionFinding

log = logging.getLogger("aegis.demo")

DEMO_MIX: tuple[tuple[str, int], ...] = (
    ("true_positive", 1),
    ("false_positive", 3),
    ("escalate", 1),
)


@dataclass
class DemoCase:
    alert: DetectionFinding
    gold_label: str
    fp_type: str | None
    dataset: str | None
    investigation_id: str | None = None
    verdict: str | None = None
    confidence: float | None = None
    cited: bool | None = None
    seconds: float = 0.0
    memory_prior: dict[str, Any] | None = None


def pick_demo_alerts(bench_dir: Path, *, split: str = "test", seed: int = 7) -> list[DemoCase]:
    """1 TP, 3 FP (distinct fp_types), 1 ambiguous from the frozen benchmark; deterministic."""
    import random

    from bench.build_benchmark import load_benchmark

    entries = [e for e in load_benchmark(bench_dir) if e.split == split]
    rng = random.Random(seed)
    rng.shuffle(entries)
    picked: list[DemoCase] = []
    seen_fp: set[str] = set()
    for label, want in DEMO_MIX:
        n = 0
        for e in entries:
            if e.gold_label != label or n >= want:
                continue
            if label == "false_positive":
                if (e.fp_type or "") in seen_fp:
                    continue
                seen_fp.add(e.fp_type or "")
            picked.append(
                DemoCase(
                    alert=DetectionFinding.model_validate(e.alert),
                    gold_label=e.gold_label,
                    fp_type=e.fp_type,
                    dataset=e.dataset,
                )
            )
            n += 1
    order = {"true_positive": 0, "false_positive": 1, "escalate": 2}
    picked.sort(key=lambda c: order[c.gold_label])
    return picked


def run_demo(
    *,
    snapshot: Path,
    bench_dir: Path,
    reset: bool = True,
    reasoner_kind: str = "auto",
    triage_path: Path | None = None,
    ui_url: str = "http://localhost:3000",
    on_case: Callable[[DemoCase], None] | None = None,
) -> dict[str, Any]:
    from aegis.api.store import Store
    from aegis.graph.deps import Deps
    from aegis.graph.reasoner import HeuristicReasoner
    from aegis.graph.runner import run_investigation
    from aegis.llm.budget import log_allowlist, reset_guard
    from aegis.llm.router import LLMRouter
    from aegis.memory.store import open_memory
    from aegis.siem.duckdb import DuckDBSiem

    t_start = time.perf_counter()
    log_allowlist()
    reset_guard()
    store = Store()
    if reset:
        store.reset_investigations()
        mem_path = Path(os.environ.get("AEGIS_DATA_ROOT", "data")) / "memory.db"
        for p in (mem_path, mem_path.with_suffix(".pulse_schema.json")):
            if p.exists():
                p.unlink()
    memory = open_memory()

    router = LLMRouter(timeout_s=float(os.environ.get("AEGIS_DEMO_LLM_TIMEOUT_S", "60")))
    reasoner: Any = HeuristicReasoner()
    if reasoner_kind != "heuristic" and router.available:
        from aegis.graph.llm_reasoner import LLMReasoner

        reasoner = LLMReasoner(router)
    triage = None
    if triage_path and triage_path.exists():
        from aegis.models.triage import load_triage

        triage = load_triage(triage_path)

    cases = pick_demo_alerts(bench_dir)
    siem = DuckDBSiem(snapshot)
    deps = Deps(
        siem=siem,
        reasoner=reasoner,
        pack_path=str(snapshot / "rules" / "sigma_pack.jsonl"),
        memory=memory,
        triage=triage,
    )
    try:
        for c in cases:
            t0 = time.perf_counter()
            res = run_investigation(c.alert, deps)
            store.save_result(res, gold_label=c.gold_label, dataset=c.dataset, fp_type=c.fp_type)
            c.investigation_id = res.investigation_id
            c.verdict = res.verdict.label if res.verdict else None
            c.confidence = res.verdict.confidence if res.verdict else None
            c.cited = bool((res.report_json or {}).get("citations_ok", True))
            c.seconds = round(time.perf_counter() - t0, 2)
            c.memory_prior = res.memory_prior
            if on_case:
                on_case(c)
    finally:
        siem.close()
        if hasattr(memory, "flush_priors"):
            memory.flush_priors()

    ambiguous = next((c for c in cases if c.gold_label == "escalate"), cases[-1])
    d = router.describe()
    return {
        "cases": [
            {
                "investigation_id": c.investigation_id,
                "gold_label": c.gold_label,
                "fp_type": c.fp_type,
                "verdict": c.verdict,
                "confidence": c.confidence,
                "cited": c.cited,
                "seconds": c.seconds,
                "url": f"{ui_url}/investigations/{c.investigation_id}",
            }
            for c in cases
        ],
        "open": f"{ui_url}/investigations/{ambiguous.investigation_id}",
        "memory": memory.status(),
        "reasoner": getattr(reasoner, "name", "heuristic"),
        "llm": d,
        "fallbacks": getattr(reasoner, "fallbacks", 0),
        "seconds": round(time.perf_counter() - t_start, 2),
    }
