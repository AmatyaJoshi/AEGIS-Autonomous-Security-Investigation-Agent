"""Ground-truth table (SPEC §5.2).

A ``GroundTruthWindow`` says: *on host H (and optionally as user U), between start and end, the
activity is adversary emulation for technique T of scenario S*. Windows come from three places:

1. the Atomic Red Team runner (``lab/emulation/runner.py``) - one row per executed atomic;
2. public dataset loaders - one row per published sample, spanning the sample's events, with the
   technique(s) from the dataset's own metadata (OTRF ``attack_mappings``, EVTX filename tags,
   BOTS answer sheets, CIC-IDS flow labels);
3. the benign-noise generators - rows with ``label = "fp"`` and an ``fp_type``.

``label_events`` joins events to windows deterministically. The result feeds the benchmark labeller
(Phase 5) and the triage-model dataset builder (Phase 6). Human review in the UI (Phase 4) can
override, but the automatic label is always kept alongside for audit.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import pyarrow as pa
import pyarrow.parquet as pq
from lab.common.ecs import EcsEvent
from pydantic import BaseModel, ConfigDict, Field, field_validator

Label = Literal["tp", "fp", "ambiguous"]

TACTIC_NAMES: dict[str, str] = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0011": "command-and-control",
    "TA0010": "exfiltration",
    "TA0040": "impact",
}
TACTIC_IDS: dict[str, str] = {v: k for k, v in TACTIC_NAMES.items()}


class GroundTruthWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_id: str
    scenario_id: str  # e.g. "otrf:SDWIN-190301125905" or "art:phish-to-dcsync"
    step: int = 0
    label: Label = "tp"
    techniques: list[str] = Field(default_factory=list)  # ["T1003.001"]
    tactics: list[str] = Field(default_factory=list)  # ["TA0006"]
    host: str | None = None  # None -> applies to every host in the dataset_ref
    user: str | None = None
    start_ts: datetime
    end_ts: datetime
    dataset: str
    dataset_ref: str
    fp_type: str | None = None  # only for label == "fp"
    source: str  # "otrf_metadata" | "evtx_filename" | "art_runner" | "bots_answers" | ...
    notes: str | None = None
    reviewed: bool = False

    @field_validator("techniques")
    @classmethod
    def _norm_tech(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for t in v:
            t = t.strip().upper()
            if not t.startswith("T"):
                raise ValueError(f"bad technique id {t!r}")
            if t not in out:
                out.append(t)
        return out

    @field_validator("tactics")
    @classmethod
    def _norm_tactic(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for t in v:
            t = t.strip()
            tid = t.upper() if t.upper().startswith("TA") else TACTIC_IDS.get(t.lower(), t)
            if tid not in out:
                out.append(tid)
        return out

    @field_validator("start_ts", "end_ts", mode="after")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)

    def contains(self, ev: EcsEvent) -> bool:
        if ev.dataset != self.dataset or ev.dataset_ref != self.dataset_ref:
            return False
        if not (self.start_ts <= ev.timestamp <= self.end_ts):
            return False
        if self.host and ev.host_name and ev.host_name.upper() != self.host.upper():
            return False
        return not (self.user and ev.user_name and ev.user_name.lower() != self.user.lower())


GT_SCHEMA = pa.schema(
    [
        pa.field("window_id", pa.string(), nullable=False),
        pa.field("scenario_id", pa.string(), nullable=False),
        pa.field("step", pa.int64()),
        pa.field("label", pa.string(), nullable=False),
        pa.field("techniques", pa.list_(pa.string())),
        pa.field("tactics", pa.list_(pa.string())),
        pa.field("host", pa.string()),
        pa.field("user", pa.string()),
        pa.field("start_ts", pa.timestamp("us", tz="UTC"), nullable=False),
        pa.field("end_ts", pa.timestamp("us", tz="UTC"), nullable=False),
        pa.field("dataset", pa.string(), nullable=False),
        pa.field("dataset_ref", pa.string(), nullable=False),
        pa.field("fp_type", pa.string()),
        pa.field("source", pa.string(), nullable=False),
        pa.field("notes", pa.string()),
        pa.field("reviewed", pa.bool_()),
    ]
)


class GroundTruthTable:
    """Append-only JSONL + Parquet writer/reader under ``data/ground_truth/``."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.jsonl = self.root / "windows.jsonl"

    def append(self, windows: Iterable[GroundTruthWindow]) -> int:
        existing = {w.window_id for w in self.read()}
        n = 0
        with self.jsonl.open("a", encoding="utf-8") as f:
            for w in windows:
                if w.window_id in existing:
                    continue
                f.write(w.model_dump_json() + "\n")
                existing.add(w.window_id)
                n += 1
        return n

    def read(self) -> list[GroundTruthWindow]:
        if not self.jsonl.exists():
            return []
        out: list[GroundTruthWindow] = []
        with self.jsonl.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    out.append(GroundTruthWindow.model_validate_json(line))
        return out

    def to_parquet(self, path: Path | None = None) -> Path:
        path = path or (self.root / "windows.parquet")
        rows = [w.model_dump() for w in self.read()]
        table = pa.Table.from_pylist(rows, schema=GT_SCHEMA)
        pq.write_table(table, path, compression="zstd")
        return path

    def coverage(self) -> dict[str, Any]:
        wins = self.read()
        tps = [w for w in wins if w.label == "tp"]
        techniques = sorted({t for w in tps for t in w.techniques})
        parents = sorted({t.split(".")[0] for t in techniques})
        tactics = sorted({t for w in tps for t in w.tactics})
        fp_types = sorted({w.fp_type for w in wins if w.fp_type})
        by_source: dict[str, int] = {}
        for w in wins:
            by_source[w.source] = by_source.get(w.source, 0) + 1
        return {
            "windows": len(wins),
            "tp_windows": len(tps),
            "fp_windows": sum(1 for w in wins if w.label == "fp"),
            "techniques": techniques,
            "technique_count": len(techniques),
            "parent_technique_count": len(parents),
            "tactics": tactics,
            "tactic_count": len(tactics),
            "fp_types": fp_types,
            "by_source": by_source,
        }


def label_events(
    events: Iterable[EcsEvent], windows: list[GroundTruthWindow]
) -> Iterator[tuple[EcsEvent, GroundTruthWindow | None]]:
    """Attach the first matching window (most specific first: host+user > host > any)."""
    by_ref: dict[tuple[str, str], list[GroundTruthWindow]] = {}
    for w in windows:
        by_ref.setdefault((w.dataset, w.dataset_ref), []).append(w)
    for ws in by_ref.values():
        ws.sort(key=lambda w: (w.host is None, w.user is None, w.start_ts))
    for ev in events:
        match = next(
            (w for w in by_ref.get((ev.dataset, ev.dataset_ref), []) if w.contains(ev)), None
        )
        yield ev, match


def dump_windows_json(windows: list[GroundTruthWindow], path: Path) -> None:
    path.write_text(json.dumps([w.model_dump(mode="json") for w in windows], indent=1))
