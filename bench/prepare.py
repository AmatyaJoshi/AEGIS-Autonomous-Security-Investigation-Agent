"""Materialise the benchmark's noise and ambiguous events into the snapshot (SPEC §8.1, §8.5).

The benchmark's false-positive and ambiguous alerts reference benign/borderline events. For the
investigation to gather and cite the surrounding context, those events must live in the same
snapshot the agent queries. This regenerates the benchmark noise (large, deterministic) and the
ambiguous events into the Parquet staging area; the caller then re-runs ``aegis lab snapshot``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.ingest.noise_alerts import (
    BENCH_NOISE_DAYS,
    BENCH_NOISE_PER_DAY,
    BENCH_NOISE_SEED,
    generate_ambiguous,
)
from lab.common.sink import ParquetSink
from lab.emulation.ground_truth import GroundTruthTable, GroundTruthWindow
from lab.pipeline import generate_noise


def prepare_bench_events(data_root: Path, *, n_ambiguous: int = 30) -> dict[str, Any]:
    parquet = data_root / "parquet"
    sink = ParquetSink(parquet)
    gt = GroundTruthTable(data_root / "ground_truth")

    # 1) large deterministic benign noise (same seed/config the benchmark FP alerts use)
    noise_rep = generate_noise(
        sink, gt, seed=BENCH_NOISE_SEED, days=BENCH_NOISE_DAYS, episodes_per_day=BENCH_NOISE_PER_DAY
    )

    # 2) ambiguous events + their gold-escalate windows
    amb_events = 0
    windows: list[GroundTruthWindow] = []
    from datetime import timedelta

    for events, rec in generate_ambiguous(n_ambiguous):
        amb_events += sink.write(events)
        windows.append(
            GroundTruthWindow(
                window_id=f"ambiguous:{rec.scenario_id}:{rec.triggering_event_id[:8]}",
                scenario_id=rec.scenario_id or "ambiguous",
                label="ambiguous",
                techniques=rec.gold_techniques,
                start_ts=min(e.timestamp for e in events) - timedelta(seconds=2),
                end_ts=max(e.timestamp for e in events) + timedelta(seconds=2),
                dataset="noise",
                dataset_ref="ambiguous",
                source="ambiguous_generator",
                host=rec.alert.hostnames()[0] if rec.alert.hostnames() else None,
            )
        )
    gt.append(windows)
    return {
        "noise_events": noise_rep.events,
        "noise_episodes": noise_rep.refs,
        "ambiguous_events": amb_events,
        "ambiguous_windows": len(windows),
    }
