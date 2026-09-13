"""Assemble the labelled benchmark alert set (SPEC §8.1).

Composition target: ~45% true-positive (stratified across tactics), ~50% false-positive (stratified
across fp_types), ~5% genuinely ambiguous (gold ``escalate``). Splits are by *scenario* (train 60 /
val 15 / test 25) so no scenario leaks across splits. The result is a frozen manifest with a content
hash of every alert; a compact hash-only manifest is committed under ``bench/manifests`` while the
full manifest (with serialised OCSF alerts) is written under ``data/benchmark`` (regenerable).

Sources:
* TP alerts  - Sigma matches over the attack datasets (otrf / evtx / lab_emulation).
* FP alerts  - one per benign-noise episode (:mod:`aegis.ingest.noise_alerts`), across all fp_types.
* Ambiguous  - borderline dual-use activity against sensitive targets (author-labelled ``escalate``;
  offline there is no independent co-labeller, so Cohen's kappa is not computed - a documented
  limitation, see RESULTS.md).
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.ingest.generate import AlertRecord, generate_alerts
from aegis.ingest.noise_alerts import FP_TYPE_RULE, generate_ambiguous, generate_noise_fp_alerts

BENCH_VERSION = "v1"
SPLITS = {"train": 0.60, "val": 0.15, "test": 0.25}


@dataclass
class BenchmarkEntry:
    alert_id: str
    gold_label: str
    gold_techniques: list[str]
    fp_type: str | None
    scenario_id: str | None
    dataset: str | None
    split: str
    content_hash: str
    alert: dict[str, Any] = field(default_factory=dict)


def _content_hash(rec: AlertRecord) -> str:
    payload = {
        "title": rec.alert.finding_info.title,
        "techniques": rec.alert.technique_ids,
        "event": rec.triggering_event_id,
        "gold": rec.gold_label,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def _collect_tp(snapshot: Path, pack: Path, target: int, seed: int) -> list[AlertRecord]:
    out: list[AlertRecord] = []
    seen: set[str] = set()
    per_tactic: Counter[str] = Counter()
    for rec in generate_alerts(
        snapshot,
        pack_path=pack,
        seed=seed,
        max_events=200000,
        datasets=("otrf", "evtx_attack", "lab_emulation"),
    ):
        if rec.gold_label != "true_positive":
            continue
        if rec.alert.alert_id in seen:
            continue
        seen.add(rec.alert.alert_id)
        out.append(rec)
        for t in rec.gold_techniques:
            per_tactic[t] += 1
        if len(out) >= target:
            break
    return out


def _collect_fp(target: int, seed: int) -> list[AlertRecord]:
    out: list[AlertRecord] = []
    by_type: dict[str, list[AlertRecord]] = defaultdict(list)
    for rec in generate_noise_fp_alerts(seed=seed, days=90, per_day=24):
        by_type[rec.fp_type or "other"].append(rec)
        if sum(len(v) for v in by_type.values()) >= target * 3:
            break
    # round-robin across fp_types for stratification
    idx = 0
    types = list(by_type)
    while len(out) < target and any(by_type.values()):
        t = types[idx % len(types)]
        if by_type[t]:
            out.append(by_type[t].pop())
        idx += 1
        if idx > target * 10:
            break
    return out[:target]


def _ambiguous(n: int) -> list[AlertRecord]:
    return [rec for _events, rec in generate_ambiguous(n)]


def _assign_splits(records: list[AlertRecord], seed: int) -> dict[str, str]:
    """Split by scenario (no scenario in two splits) while balancing alert COUNTS per split.

    Greedy bin-packing per gold label: within each label, scenarios are sorted largest-first and
    each is placed in the split currently furthest below its target share. This keeps splits close
    to 60/15/25 for every label without leaking a scenario across splits.
    """
    rng = random.Random(seed)
    by_scenario: dict[str, list[AlertRecord]] = defaultdict(list)
    for r in records:
        by_scenario[r.scenario_id or r.rule_id].append(r)
    split_of: dict[str, str] = {}
    labels = ("true_positive", "false_positive", "escalate")
    for label in labels:
        scen_sizes = [(sc, len(rs)) for sc, rs in by_scenario.items() if rs[0].gold_label == label]
        rng.shuffle(scen_sizes)
        scen_sizes.sort(key=lambda x: x[1], reverse=True)
        total = sum(s for _, s in scen_sizes)
        counts = {s: 0 for s in SPLITS}
        for sc, size in scen_sizes:
            # deficit = target - current, pick the neediest split
            best = max(SPLITS, key=lambda s: SPLITS[s] * total - counts[s])
            split_of[sc] = best
            counts[best] += size
    return split_of


def build_benchmark(
    snapshot_dir: Path,
    out_dir: Path,
    *,
    total: int = 420,
    seed: int = 1337,
) -> dict[str, Any]:
    pack = snapshot_dir / "rules" / "sigma_pack.jsonl"
    n_tp = int(total * 0.45)
    n_fp = int(total * 0.50)
    n_amb = total - n_tp - n_fp
    tp = _collect_tp(snapshot_dir, pack, n_tp, seed)
    fp = _collect_fp(n_fp, seed)
    amb = _ambiguous(n_amb)
    records = tp + fp + amb
    split_of = _assign_splits(records, seed)

    entries: list[BenchmarkEntry] = []
    for rec in records:
        sc = rec.scenario_id or rec.rule_id
        entries.append(
            BenchmarkEntry(
                alert_id=rec.alert.alert_id,
                gold_label=rec.gold_label,
                gold_techniques=rec.gold_techniques,
                fp_type=rec.fp_type,
                scenario_id=rec.scenario_id,
                dataset=rec.dataset,
                split=split_of[sc],
                content_hash=_content_hash(rec),
                alert=rec.alert.model_dump(mode="json"),
            )
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    full_path = out_dir / f"benchmark_{BENCH_VERSION}.json"
    full_path.write_text(json.dumps([asdict(e) for e in entries], default=str), encoding="utf-8")

    # Frozen hash-only manifest (committed).
    frozen = {
        "version": BENCH_VERSION,
        "created": datetime.now(tz=UTC).isoformat(),
        "seed": seed,
        "total": len(entries),
        "composition": dict(Counter(e.gold_label for e in entries)),
        "fp_types": dict(Counter(e.fp_type for e in entries if e.fp_type)),
        "splits": dict(Counter(e.split for e in entries)),
        "tactics_covered": len({t for e in entries for t in e.gold_techniques}),
        "manifest_hash": hashlib.sha256(
            "".join(sorted(e.content_hash for e in entries)).encode()
        ).hexdigest(),
        "entries": [
            {
                "alert_id": e.alert_id,
                "gold_label": e.gold_label,
                "fp_type": e.fp_type,
                "split": e.split,
                "content_hash": e.content_hash,
                "scenario_id": e.scenario_id,
            }
            for e in entries
        ],
    }
    frozen_dir = Path(__file__).parent / "manifests"
    frozen_dir.mkdir(parents=True, exist_ok=True)
    (frozen_dir / f"benchmark_{BENCH_VERSION}.frozen.json").write_text(
        json.dumps(frozen, indent=1), encoding="utf-8"
    )
    summary = {
        k: frozen[k]
        for k in (
            "version",
            "total",
            "composition",
            "splits",
            "fp_types",
            "tactics_covered",
            "manifest_hash",
        )
    }
    summary["full_manifest"] = str(full_path)
    summary["fp_type_rules"] = len(FP_TYPE_RULE)
    return summary


def load_benchmark(out_dir: Path, version: str = BENCH_VERSION) -> list[BenchmarkEntry]:
    path = out_dir / f"benchmark_{version}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return [BenchmarkEntry(**e) for e in data]
