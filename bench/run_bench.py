"""Run the benchmark comparison arms (SPEC §8.2) and emit per-alert predictions.

Arms:
  (a) rules_only        - verdict straight from the detecting rule's severity, no context.
  (b) single_shot_llm   - the reasoner sees only the raw alert (no tools, no context, no evidence).
  (c) aegis_no_triage   - the full investigation graph with the reasoner, no triage fast-path.
  (d) aegis_full        - the full graph plus the triage model (fast-path + score blend).

Offline, arms (b)-(d) use the deterministic ``HeuristicReasoner``; with an API key the same arms use
``LLMReasoner`` (a real single call for arm b). Predictions carry a ``malicious_score`` so the FP
suppression / ROC metrics can threshold a single continuous score per arm.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from aegis.graph.deps import Deps
from aegis.graph.reasoner import HeuristicReasoner
from aegis.graph.runner import run_investigation
from aegis.graph.state import ContextBundle
from aegis.schema.ocsf import DetectionFinding, SeverityId
from aegis.siem.duckdb import DuckDBSiem

from bench.build_benchmark import BenchmarkEntry, load_benchmark

ARMS = ("rules_only", "single_shot_llm", "aegis_no_triage", "aegis_full")


@dataclass
class Prediction:
    alert_id: str
    gold_label: str
    gold_techniques: list[str]
    fp_type: str | None
    split: str
    pred_label: str
    malicious_score: float
    confidence: float
    pred_techniques: list[str] = field(default_factory=list)
    seconds: float = 0.0
    tool_calls: int = 0
    injection_flagged: bool = False
    report_cited: bool = True


def _severity_score(alert: DetectionFinding) -> float:
    return {
        SeverityId.CRITICAL: 0.9,
        SeverityId.HIGH: 0.75,
        SeverityId.MEDIUM: 0.5,
        SeverityId.LOW: 0.25,
        SeverityId.INFORMATIONAL: 0.1,
    }.get(alert.severity_id, 0.5)


def predict_rules_only(alert: DetectionFinding) -> tuple[str, float, float, list[str]]:
    s = _severity_score(alert)
    if alert.severity_id in (SeverityId.CRITICAL, SeverityId.HIGH):
        return "true_positive", s, s, alert.technique_ids
    if alert.severity_id == SeverityId.MEDIUM:
        return "escalate", 0.5, 0.5, alert.technique_ids
    return "false_positive", s, 1 - s, []


def predict_single_shot(
    alert: DetectionFinding, reasoner: HeuristicReasoner
) -> tuple[str, float, float, list[str]]:
    # No context, no hypotheses, no evidence - the reasoner reads only the alert itself.
    v = reasoner.decide(alert, ContextBundle(), [])
    score = (
        0.5 + v.confidence / 2
        if v.label == "true_positive"
        else 0.5 - v.confidence / 2
        if v.label == "false_positive"
        else 0.5
    )
    return v.label, score, v.confidence, v.techniques


def run_arm(
    arm: str, entries: list[BenchmarkEntry], deps: Deps | None, reasoner: HeuristicReasoner
) -> list[Prediction]:
    preds: list[Prediction] = []
    for e in entries:
        alert = DetectionFinding.model_validate(e.alert)
        t0 = time.perf_counter()
        cited = True
        tool_calls = 0
        injection = False
        if arm == "rules_only":
            label, score, conf, techs = predict_rules_only(alert)
        elif arm == "single_shot_llm":
            label, score, conf, techs = predict_single_shot(alert, reasoner)
        else:
            assert deps is not None
            res = run_investigation(alert, deps)
            v = res.verdict
            assert v is not None
            label, score, conf, techs = v.label, res.malicious_score, v.confidence, v.techniques
            tool_calls = res.spent.tool_calls
            injection = res.injection_flagged
            cited = bool((res.report_json or {}).get("citations_ok", True))
        preds.append(
            Prediction(
                alert_id=e.alert_id,
                gold_label=e.gold_label,
                gold_techniques=e.gold_techniques,
                fp_type=e.fp_type,
                split=e.split,
                pred_label=label,
                malicious_score=round(score, 4),
                confidence=round(conf, 4),
                pred_techniques=techs,
                seconds=round(time.perf_counter() - t0, 4),
                tool_calls=tool_calls,
                injection_flagged=injection,
                report_cited=cited,
            )
        )
    return preds


def run_benchmark(
    snapshot_dir: Path,
    bench_dir: Path,
    out_dir: Path,
    *,
    arms: tuple[str, ...] = ARMS,
    split: str | None = None,
    triage_model: Any | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    entries = load_benchmark(bench_dir)
    if split:
        entries = [e for e in entries if e.split == split]
    if limit:
        entries = entries[:limit]
    siem = DuckDBSiem(snapshot_dir)
    reasoner = HeuristicReasoner()
    pack = str(snapshot_dir / "rules" / "sigma_pack.jsonl")
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {"split": split or "all", "n": len(entries), "arms": {}}
    try:
        for arm in arms:
            deps: Deps | None = None
            if arm == "aegis_no_triage":
                deps = Deps(siem=siem, reasoner=reasoner, pack_path=pack)
            elif arm == "aegis_full":
                deps = Deps(siem=siem, reasoner=reasoner, pack_path=pack, triage=triage_model)
            preds = run_arm(arm, entries, deps, reasoner)
            (out_dir / f"predictions_{arm}.json").write_text(
                json.dumps([asdict(p) for p in preds]), encoding="utf-8"
            )
            results["arms"][arm] = len(preds)
    finally:
        siem.close()
    return results


def load_predictions(out_dir: Path, arm: str) -> list[Prediction]:
    data = json.loads((out_dir / f"predictions_{arm}.json").read_text(encoding="utf-8"))
    return [Prediction(**p) for p in data]
