"""Score benchmark predictions (SPEC §8.3).

Primary metric: **false-positive suppression at <= 2% missed-TP**. We threshold each arm's
``malicious_score``: an alert is auto-closed (predicted benign) when its score is below the
threshold. The threshold is chosen as the largest value at which at most 2% of true-positives are
auto-closed; the metric is the fraction of false-positives auto-closed at that threshold. We also
report the full ROC-style curve, verdict accuracy / macro-F1, a confusion matrix, escalation
precision, ATT&CK technique/tactic F1, report-citation compliance, and efficiency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bench.run_bench import Prediction

LABELS = ("true_positive", "false_positive", "escalate")


@dataclass
class ArmScore:
    arm: str
    n: int
    accuracy: float
    macro_f1: float
    confusion: dict[str, dict[str, int]]
    fp_suppression_at_2pct_missed: float
    fp_suppression_threshold: float
    missed_tp_rate_at_threshold: float
    roc: list[dict[str, float]]
    escalation_precision: float
    technique_f1: float
    tactic_f1: float
    citation_rate: float
    avg_seconds: float
    avg_tool_calls: float
    per_fp_type_suppression: dict[str, float] = field(default_factory=dict)


def _confusion(preds: list[Prediction]) -> dict[str, dict[str, int]]:
    m = {g: {p: 0 for p in LABELS} for g in LABELS}
    for pr in preds:
        if pr.gold_label in m and pr.pred_label in m[pr.gold_label]:
            m[pr.gold_label][pr.pred_label] += 1
    return m


def _macro_f1(conf: dict[str, dict[str, int]]) -> float:
    f1s = []
    for label in LABELS:
        tp = conf[label][label]
        fp = sum(conf[g][label] for g in LABELS if g != label)
        fn = sum(conf[label][p] for p in LABELS if p != label)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1s.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
    return sum(f1s) / len(f1s)


def _fp_suppression(
    preds: list[Prediction], max_missed_tp: float = 0.02
) -> tuple[float, float, float, list[dict[str, float]]]:
    """Auto-close alerts scoring below a threshold; find the largest threshold with <=2% missed TP.

    Returns (fp_suppression_rate, threshold, missed_tp_rate, roc_curve).
    """
    tps = [p for p in preds if p.gold_label == "true_positive"]
    fps = [p for p in preds if p.gold_label == "false_positive"]
    if not tps or not fps:
        return 0.0, 0.0, 0.0, []
    thresholds = sorted({round(p.malicious_score, 4) for p in preds} | {0.0, 1.0})
    roc: list[dict[str, float]] = []
    best_supp = 0.0
    best_thr = 0.0
    best_missed = 0.0
    for thr in thresholds:
        # auto-close (predict benign) when score < thr
        missed_tp = sum(1 for p in tps if p.malicious_score < thr) / len(tps)
        supp_fp = sum(1 for p in fps if p.malicious_score < thr) / len(fps)
        roc.append(
            {
                "threshold": thr,
                "missed_tp_rate": round(missed_tp, 4),
                "fp_suppression": round(supp_fp, 4),
            }
        )
        if missed_tp <= max_missed_tp and supp_fp >= best_supp:
            best_supp = supp_fp
            best_thr = thr
            best_missed = missed_tp
    return best_supp, best_thr, best_missed, roc


def _escalation_precision(preds: list[Prediction]) -> float:
    escalated = [p for p in preds if p.pred_label == "escalate"]
    if not escalated:
        return 0.0
    # A "good" escalation is one that is genuinely hard: gold escalate, or a gold TP/FP the arm was
    # not confident about (correctly refusing to auto-decide a boundary case).
    good = sum(
        1 for p in escalated if p.gold_label == "escalate" or 0.35 <= p.malicious_score <= 0.65
    )
    return good / len(escalated)


def _technique_f1(
    preds: list[Prediction], tactic_level: bool = False, kb: Any | None = None
) -> float:
    tp = fp = fn = 0
    for p in preds:
        if p.gold_label == "false_positive":
            gold: set[str] = set()
        else:
            gold = set(p.gold_techniques)
        pred = set(p.pred_techniques)
        if tactic_level and kb is not None:
            gold = {t for g in gold for t in kb.tactics_for(g)}
            pred = {t for g in pred for t in kb.tactics_for(g)}
        elif not tactic_level:
            gold = {t.split(".")[0] for t in gold}
            pred = {t.split(".")[0] for t in pred}
        tp += len(gold & pred)
        fp += len(pred - gold)
        fn += len(gold - pred)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return 2 * prec * rec / (prec + rec) if prec + rec else 0.0


def _per_fp_type_suppression(preds: list[Prediction], threshold: float) -> dict[str, float]:
    from collections import defaultdict

    buckets: dict[str, list[Prediction]] = defaultdict(list)
    for p in preds:
        if p.gold_label == "false_positive" and p.fp_type:
            buckets[p.fp_type].append(p)
    return {
        t: round(sum(1 for p in ps if p.malicious_score < threshold) / len(ps), 3)
        for t, ps in sorted(buckets.items())
        if ps
    }


def score_arm(arm: str, preds: list[Prediction]) -> ArmScore:
    from aegis.attack.kb import load_kb

    conf = _confusion(preds)
    correct = sum(conf[label][label] for label in LABELS)
    n = len(preds)
    supp, thr, missed, roc = _fp_suppression(preds)
    kb = load_kb()
    return ArmScore(
        arm=arm,
        n=n,
        accuracy=round(correct / n, 4) if n else 0.0,
        macro_f1=round(_macro_f1(conf), 4),
        confusion=conf,
        fp_suppression_at_2pct_missed=round(supp, 4),
        fp_suppression_threshold=thr,
        missed_tp_rate_at_threshold=round(missed, 4),
        roc=roc,
        escalation_precision=round(_escalation_precision(preds), 4),
        technique_f1=round(_technique_f1(preds), 4),
        tactic_f1=round(_technique_f1(preds, tactic_level=True, kb=kb), 4),
        citation_rate=round(sum(p.report_cited for p in preds) / n, 4) if n else 0.0,
        avg_seconds=round(sum(p.seconds for p in preds) / n, 4) if n else 0.0,
        avg_tool_calls=round(sum(p.tool_calls for p in preds) / n, 2) if n else 0.0,
        per_fp_type_suppression=_per_fp_type_suppression(preds, thr),
    )


def score_all(out_dir: Any, arms: tuple[str, ...]) -> dict[str, Any]:
    from pathlib import Path

    from bench.run_bench import load_predictions

    out_dir = Path(out_dir)
    scores: dict[str, Any] = {}
    for arm in arms:
        path = out_dir / f"predictions_{arm}.json"
        if not path.exists():
            continue
        preds = load_predictions(out_dir, arm)
        s = score_arm(arm, preds)
        scores[arm] = {k: v for k, v in s.__dict__.items() if k != "roc"}
        scores[arm]["roc_points"] = len(s.roc)
        (out_dir / f"roc_{arm}.json").write_text(__import__("json").dumps(s.roc), encoding="utf-8")
    return scores
