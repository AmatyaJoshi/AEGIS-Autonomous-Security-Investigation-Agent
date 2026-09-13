"""Lab orchestration: load public datasets + generate noise -> Parquet + ground truth.

This is the ``aegis lab load`` / ``aegis lab noise`` engine. It is deliberately Elastic-optional: by
default everything is written to ``data/parquet`` (staging) and ``data/ground_truth``; pass an
``ElasticSink`` as well to also index into the lab SIEM. ``aegis lab snapshot`` then
consolidates the staging Parquet into an immutable, hashed snapshot for ``--offline`` mode.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from lab.common.ecs import EcsEvent
from lab.common.sink import EventSink, MultiSink, ParquetSink
from lab.datasets.evtx_attack import EvtxAttackLoader
from lab.datasets.otrf import OtrfLoader
from lab.emulation.ground_truth import GroundTruthTable, GroundTruthWindow, label_events
from lab.noise.generators import ORG_YAML, generate

log = logging.getLogger(__name__)


@dataclass
class LoadReport:
    dataset: str
    refs: int = 0
    events: int = 0
    windows: int = 0
    errors: list[str] = field(default_factory=list)


def _flush(
    sink: EventSink, gt: GroundTruthTable, events: list[EcsEvent], windows: list[GroundTruthWindow]
) -> tuple[int, int]:
    e = sink.write(events) if events else 0
    w = gt.append(windows) if windows else 0
    return e, w


def load_otrf(
    raw_dir: Path,
    sink: EventSink,
    gt: GroundTruthTable,
    *,
    limit: int | None = None,
    download: bool = True,
    client: httpx.Client | None = None,
) -> LoadReport:
    loader = OtrfLoader(raw_dir / "otrf", client=client)
    rep = LoadReport("otrf")
    metas = loader.download() if download else loader.metadata()
    for meta in metas[:limit]:
        try:
            events = list(loader.iter_events(meta))
        except Exception as e:
            rep.errors.append(f"{meta.id}: {e}")
            continue
        if not events:
            continue
        windows = loader.ground_truth(meta, events)
        ne, nw = _flush(sink, gt, events, windows)
        rep.refs += 1
        rep.events += ne
        rep.windows += nw
    return rep


def load_evtx(
    raw_dir: Path,
    sink: EventSink,
    gt: GroundTruthTable,
    *,
    limit: int | None = None,
    download: bool = True,
    client: httpx.Client | None = None,
) -> LoadReport:
    loader = EvtxAttackLoader(raw_dir / "evtx_attack", client=client)
    rep = LoadReport("evtx_attack")
    if download:
        loader.download()
    elif not loader.files():
        # Cached archive present but not yet unpacked (e.g. --no-download after a manual fetch).
        archive = loader.raw_dir / "EVTX-ATTACK-SAMPLES-master.zip"
        if archive.exists():
            loader.extract(archive)
    for path in loader.files()[:limit]:
        try:
            events = list(loader.iter_events(path))
        except Exception as e:
            rep.errors.append(f"{path.name}: {e}")
            continue
        if not events:
            continue
        windows = loader.ground_truth(path, events)
        ne, nw = _flush(sink, gt, events, windows)
        rep.refs += 1
        rep.events += ne
        rep.windows += nw
    return rep


def generate_noise(
    sink: EventSink,
    gt: GroundTruthTable,
    *,
    seed: int,
    days: int,
    episodes_per_day: int,
    start: datetime | None = None,
    org_path: Path = ORG_YAML,
) -> LoadReport:
    rep = LoadReport("noise")
    buf_events: list[EcsEvent] = []
    buf_windows: list[GroundTruthWindow] = []
    for events, window in generate(
        seed=seed, days=days, episodes_per_day=episodes_per_day, start=start, org_path=org_path
    ):
        buf_events.extend(events)
        buf_windows.append(window)
        rep.refs += 1
        if len(buf_events) >= 5000:
            ne, nw = _flush(sink, gt, buf_events, buf_windows)
            rep.events += ne
            rep.windows += nw
            buf_events, buf_windows = [], []
    ne, nw = _flush(sink, gt, buf_events, buf_windows)
    rep.events += ne
    rep.windows += nw
    return rep


def make_sink(parquet_dir: Path, elastic_sink: EventSink | None = None) -> EventSink:
    ps = ParquetSink(parquet_dir)
    return MultiSink(ps, elastic_sink) if elastic_sink else ps


def relabel_from_ground_truth(
    events: list[EcsEvent], windows: list[GroundTruthWindow]
) -> dict[str, Any]:
    """Diagnostic: how many events fall inside a labelled window (tests / `lab verify`)."""
    matched = 0
    per_label: dict[str, int] = {}
    for _ev, win in label_events(events, windows):
        if win is not None:
            matched += 1
            per_label[win.label] = per_label.get(win.label, 0) + 1
    return {"events": len(events), "matched": matched, "per_label": per_label}


def default_start() -> datetime:
    return datetime(2025, 1, 6, tzinfo=UTC)
