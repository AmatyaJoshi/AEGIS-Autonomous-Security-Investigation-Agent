"""Evaluate the triage classifier (SPEC §7.1).

Reports per-class precision/recall/F1, AUROC (TP-vs-rest), missed-TP at the chosen
fast-path threshold, calibration (ECE + reliability bins), and a per-rule / per-fp_type breakdown so
rules the model handles poorly are visible. Writes ``training/results/<date>_<sha>_triage.json``.

    python -m training.triage.eval
"""

from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.models.triage import CLASSES, FEATURE_ORDER, LightGBMTriage
from training.triage.build_dataset import load_dataset

RESULTS = Path("training") / "results"


def _predict(model: LightGBMTriage, rows: list[dict[str, Any]]) -> list[dict[str, float]]:
    out = []
    for r in rows:
        scores = model.score({"numeric": r["numeric"], "text": r.get("text", "")})
        out.append(scores)
    return out


def _prf(rows: list[dict[str, Any]], preds: list[str]) -> dict[str, Any]:
    labels = CLASSES
    conf = {g: {p: 0 for p in labels} for g in labels}
    for r, p in zip(rows, preds, strict=True):
        conf[r["label"]][p] += 1
    per_class = {}
    for label in labels:
        tp = conf[label][label]
        fp = sum(conf[g][label] for g in labels if g != label)
        fn = sum(conf[label][p] for p in labels if p != label)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        per_class[label] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(2 * prec * rec / (prec + rec) if prec + rec else 0.0, 4),
            "support": tp + fn,
        }
    macro_f1 = sum(c["f1"] for c in per_class.values()) / len(per_class)
    return {"confusion": conf, "per_class": per_class, "macro_f1": round(macro_f1, 4)}


def _auroc(y_true: list[int], scores: list[float]) -> float:
    # AUROC via rank statistic (Mann-Whitney U). y_true: 1 for TP, 0 otherwise.
    pos = [s for s, y in zip(scores, y_true, strict=True) if y == 1]
    neg = [s for s, y in zip(scores, y_true, strict=True) if y == 0]
    if not pos or not neg:
        return 0.0
    ranked = sorted(zip(scores, y_true, strict=True), key=lambda x: x[0])
    rank_sum = 0.0
    i = 0
    r = 1
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg_rank = (r + (r + (j - i) - 1)) / 2
        for k in range(i, j):
            if ranked[k][1] == 1:
                rank_sum += avg_rank
        r += j - i
        i = j
    return (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def _ece(
    y_true: list[int], probs: list[float], bins: int = 10
) -> tuple[float, list[dict[str, float]]]:
    buckets: list[list[tuple[int, float]]] = [[] for _ in range(bins)]
    for y, p in zip(y_true, probs, strict=True):
        idx = min(bins - 1, int(p * bins))
        buckets[idx].append((y, p))
    ece = 0.0
    reliability = []
    n = len(y_true)
    for b, items in enumerate(buckets):
        if not items:
            reliability.append({"bin": b / bins, "conf": 0.0, "acc": 0.0, "n": 0})
            continue
        acc = sum(y for y, _ in items) / len(items)
        conf = sum(p for _, p in items) / len(items)
        ece += len(items) / n * abs(acc - conf)
        reliability.append(
            {
                "bin": round(b / bins, 2),
                "conf": round(conf, 4),
                "acc": round(acc, 4),
                "n": len(items),
            }
        )
    return round(ece, 4), reliability


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "nogit"


def evaluate(model_path: Path, data_dir: Path, fast_path_pfp: float = 0.90) -> dict[str, Any]:
    model = LightGBMTriage(model_path)
    rows = [r for r in load_dataset(data_dir) if r["split"] == "test"]
    scores = _predict(model, rows)
    preds = [
        max(
            CLASSES,
            key=lambda c: s[
                f"p_{
                    'fp' if c == 'false_positive' else 'tp' if c == 'true_positive' else 'escalate'
                }"
            ],
        )
        for s in scores
    ]
    prf = _prf(rows, preds)

    y_tp = [1 if r["label"] == "true_positive" else 0 for r in rows]
    p_tp = [s["p_tp"] for s in scores]
    auroc = _auroc(y_tp, p_tp)
    ece, reliability = _ece(y_tp, p_tp)

    # Fast-path: auto-close FP when p_fp > threshold. Missed-TP = TP alerts auto-closed.
    tps = [(r, s) for r, s in zip(rows, scores, strict=True) if r["label"] == "true_positive"]
    fps = [(r, s) for r, s in zip(rows, scores, strict=True) if r["label"] == "false_positive"]
    missed = sum(1 for _r, s in tps if s["p_fp"] > fast_path_pfp) / len(tps) if tps else 0.0
    fast_path_rate = sum(1 for _r, s in fps if s["p_fp"] > fast_path_pfp) / len(fps) if fps else 0.0

    per_fp_type: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "correct": 0})
    for r, p in zip(rows, preds, strict=True):
        if r["fp_type"]:
            per_fp_type[r["fp_type"]]["n"] += 1
            per_fp_type[r["fp_type"]]["correct"] += int(p == r["label"])

    result = {
        "model": str(model_path),
        "n_test": len(rows),
        "macro_f1": prf["macro_f1"],
        "per_class": prf["per_class"],
        "confusion": prf["confusion"],
        "auroc_tp_vs_rest": round(auroc, 4),
        "ece": ece,
        "reliability": reliability,
        "fast_path_threshold_pfp": fast_path_pfp,
        "missed_tp_at_fast_path": round(missed, 4),
        "fast_path_rate": round(fast_path_rate, 4),
        "per_fp_type": {
            k: {**v, "accuracy": round(v["correct"] / v["n"], 3)}
            for k, v in sorted(per_fp_type.items())
        },
        "features": FEATURE_ORDER,
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = f"{datetime.now(tz=UTC).strftime('%Y%m%d')}_{_git_sha()}_triage"
    (RESULTS / f"{stamp}.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    return result


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="training/triage/artifacts/model.txt")
    ap.add_argument("--data", default="training/triage/data")
    args = ap.parse_args()
    print(json.dumps(evaluate(Path(args.model), Path(args.data)), indent=1))
