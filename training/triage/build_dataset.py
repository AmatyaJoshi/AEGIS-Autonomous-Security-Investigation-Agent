"""Build the triage-classifier training dataset (SPEC §7.1).

For each benchmark alert we enrich context (asset / identity / TI / sigma re-match) exactly as the
live graph does, serialise the fixed feature template, and pair it with the gold label. Output is a
JSONL of ``{numeric, text, label, split, fp_type, rule_id, scenario_id}`` plus a datacard. Splitting
is inherited from the frozen benchmark manifest (scenario-disjoint), so there is no leakage.

    python -m training.triage.build_dataset --snapshot dev
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from aegis.graph.context_build import build_context
from aegis.graph.deps import Deps
from aegis.graph.reasoner import HeuristicReasoner
from aegis.models.triage import serialize_features
from aegis.schema.ocsf import DetectionFinding
from aegis.siem.duckdb import DuckDBSiem
from bench.build_benchmark import load_benchmark

OUT = Path("training") / "triage" / "data"


def build(snapshot_dir: Path, bench_dir: Path, out_dir: Path = OUT) -> dict[str, Any]:
    entries = load_benchmark(bench_dir)
    siem = DuckDBSiem(snapshot_dir)
    deps = Deps(
        siem=siem,
        reasoner=HeuristicReasoner(),
        pack_path=str(snapshot_dir / "rules" / "sigma_pack.jsonl"),
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    try:
        for e in entries:
            alert = DetectionFinding.model_validate(e.alert)
            ctx, _ = build_context(alert, deps)
            feats = serialize_features(alert, ctx)
            rows.append(
                {
                    "numeric": feats["numeric"],
                    "text": feats["text"],
                    "label": e.gold_label,
                    "split": e.split,
                    "fp_type": e.fp_type,
                    "scenario_id": e.scenario_id,
                    "alert_id": e.alert_id,
                }
            )
    finally:
        siem.close()
    (out_dir / "triage_dataset.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows), encoding="utf-8"
    )

    from collections import Counter

    card = {
        "n": len(rows),
        "labels": dict(Counter(r["label"] for r in rows)),
        "by_split": {
            s: dict(Counter(r["label"] for r in rows if r["split"] == s))
            for s in ("train", "val", "test")
        },
        "fp_types": dict(Counter(r["fp_type"] for r in rows if r["fp_type"])),
        "features": list(rows[0]["numeric"].keys()) if rows else [],
    }
    (out_dir / "datacard.json").write_text(json.dumps(card, indent=1), encoding="utf-8")
    return card


def load_dataset(out_dir: Path = OUT) -> list[dict[str, Any]]:
    path = out_dir / "triage_dataset.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


if __name__ == "__main__":
    import argparse

    from aegis.config import get_settings

    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", default="dev")
    args = ap.parse_args()
    s = get_settings()
    card = build(s.data.snapshots / args.snapshot, s.data.root / "benchmark")
    print(json.dumps(card, indent=1))
    _ = asdict  # keep import meaningful
