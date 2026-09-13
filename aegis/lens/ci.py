"""`lens ci` gate (SPEC §10): run the small benchmark suite + Lens metrics and enforce thresholds.

Fails (non-zero) if any gate is breached, so CI blocks a regression. Gates are conservative defaults
tuned to the offline heuristic baseline; tighten them as the models improve.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bench.build_benchmark import load_benchmark

from aegis.graph.deps import Deps
from aegis.graph.reasoner import HeuristicReasoner
from aegis.graph.runner import run_investigation
from aegis.lens.metrics import aggregate, evaluate_investigation
from aegis.schema.ocsf import DetectionFinding
from aegis.siem.duckdb import DuckDBSiem


@dataclass
class Gate:
    name: str
    value: float
    threshold: float
    ok: bool
    direction: str  # ">=" or "<="


def run_ci(
    snapshot_dir: Path,
    bench_dir: Path,
    *,
    split: str = "test",
    limit: int = 40,
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    thresholds = thresholds or {
        "report_faithfulness": 0.95,
        "tool_call_correctness": 0.99,
        "verdict_accuracy": 0.75,
    }
    entries = [e for e in load_benchmark(bench_dir) if e.split == split][:limit]
    siem = DuckDBSiem(snapshot_dir)
    deps = Deps(
        siem=siem,
        reasoner=HeuristicReasoner(),
        pack_path=str(snapshot_dir / "rules" / "sigma_pack.jsonl"),
    )
    metrics = []
    correct = 0
    try:
        for e in entries:
            alert = DetectionFinding.model_validate(e.alert)
            res = run_investigation(alert, deps)
            metrics.append(evaluate_investigation(res, siem, gold_label=e.gold_label))
            if res.verdict and res.verdict.label == e.gold_label:
                correct += 1
    finally:
        siem.close()
    agg = aggregate(metrics)
    accuracy = correct / len(entries) if entries else 0.0
    gates = [
        Gate(
            "report_faithfulness",
            agg["mean_report_faithfulness"],
            thresholds["report_faithfulness"],
            agg["mean_report_faithfulness"] >= thresholds["report_faithfulness"],
            ">=",
        ),
        Gate(
            "tool_call_correctness",
            agg["mean_tool_call_correctness"],
            thresholds["tool_call_correctness"],
            agg["mean_tool_call_correctness"] >= thresholds["tool_call_correctness"],
            ">=",
        ),
        Gate(
            "verdict_accuracy",
            round(accuracy, 4),
            thresholds["verdict_accuracy"],
            accuracy >= thresholds["verdict_accuracy"],
            ">=",
        ),
    ]
    return {
        "passed": all(g.ok for g in gates),
        "n": len(entries),
        "accuracy": round(accuracy, 4),
        "lens": agg,
        "gates": [g.__dict__ for g in gates],
    }


if __name__ == "__main__":  # pragma: no cover
    import argparse
    import sys

    from aegis.config import get_settings

    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", default="dev")
    ap.add_argument("--limit", type=int, default=40)
    args = ap.parse_args()
    s = get_settings()
    report = run_ci(s.data.snapshots / args.snapshot, s.data.root / "benchmark", limit=args.limit)
    print(json.dumps(report, indent=1))
    sys.exit(0 if report["passed"] else 1)
