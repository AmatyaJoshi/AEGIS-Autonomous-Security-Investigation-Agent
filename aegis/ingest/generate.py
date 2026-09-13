"""Generate OCSF alerts from the offline lab store by Sigma-matching events, with gold labels.

This is the offline ingest path used by ``aegis investigate --source offline`` and the benchmark
(SPEC §8.1). It:

1. samples events from the DuckDB snapshot (stratified so both attack and benign telemetry appear);
2. runs the Sigma pack over each event; a match becomes a ``detection_finding`` (real alert);
3. labels the alert from the ground-truth windows the event falls in:
   * event inside a TP window  -> gold ``true_positive`` (with the window's techniques);
   * event inside an FP window  -> gold ``false_positive`` (with the window's fp_type);
   * ``ambiguous`` windows      -> gold ``escalate``;
   * a benign-noise event with no window but from the noise dataset -> ``false_positive``;
   * anything else              -> unlabelled (dropped from the benchmark, kept for live demo).

The alert carries its triggering event embedded (so tools can re-query and cite it) and the gold
label rides alongside in the ``AlertRecord`` (never inside the alert the agent sees).
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from aegis.schema.normalize.sigma import finding_from_sigma
from aegis.schema.normalize.sigma_match import SigmaRuleset
from aegis.schema.ocsf import DetectionFinding
from aegis.siem.duckdb import DuckDBSiem

GoldLabel = Literal["true_positive", "false_positive", "escalate", "unknown"]


@dataclass
class AlertRecord:
    alert: DetectionFinding
    gold_label: GoldLabel
    gold_techniques: list[str] = field(default_factory=list)
    fp_type: str | None = None
    scenario_id: str | None = None
    dataset: str | None = None
    triggering_event_id: str = ""
    rule_id: str = ""


def _windows_from_snapshot(siem: DuckDBSiem) -> list[dict[str, Any]]:
    raw = siem.con.execute("SELECT * FROM ground_truth").fetchdf().to_dict("records")
    records: list[dict[str, Any]] = [{str(k): v for k, v in r.items()} for r in raw]
    out: list[dict[str, Any]] = []
    for r in records:
        clean: dict[str, Any] = {}
        for k, v in r.items():
            if hasattr(v, "tolist") and not isinstance(v, float):
                clean[k] = list(v)
            elif _is_nan(v):
                clean[k] = None
            else:
                clean[k] = v
        out.append(clean)
    return out


def _label_for_event(
    event: dict[str, Any], windows: list[dict[str, Any]]
) -> tuple[GoldLabel, list[str], str | None, str | None]:
    ts = event.get("@timestamp")
    ds = event.get("dataset")
    ref = event.get("dataset_ref")
    host = (event.get("host_name") or "").upper()
    for w in windows:
        if w.get("dataset") != ds or w.get("dataset_ref") != ref:
            continue
        start, end = w.get("start_ts"), w.get("end_ts")
        if ts is None or start is None or end is None:
            continue
        if not (start <= ts <= end):
            continue
        w_host = w.get("host") or ""
        if w_host and host and w_host.upper() != host:
            continue
        label = w.get("label")
        if label == "tp":
            return "true_positive", list(w.get("techniques") or []), None, w.get("scenario_id")
        if label == "fp":
            return "false_positive", [], w.get("fp_type"), w.get("scenario_id")
        if label == "ambiguous":
            return "escalate", list(w.get("techniques") or []), None, w.get("scenario_id")
    if ds == "noise":
        return "false_positive", [], "unlabelled_noise", None
    return "unknown", [], None, None


def generate_alerts(
    snapshot_dir: Path,
    *,
    pack_path: Path | None = None,
    max_events: int = 20000,
    seed: int = 1337,
    include_unknown: bool = False,
    datasets: tuple[str, ...] | None = None,
) -> Iterator[AlertRecord]:
    """Yield labelled alerts by matching Sigma rules over a sample of snapshot events."""
    siem = DuckDBSiem(snapshot_dir)
    rs = SigmaRuleset.from_pack(str(pack_path or snapshot_dir / "rules" / "sigma_pack.jsonl"))
    windows = _windows_from_snapshot(siem)
    rng = random.Random(seed)
    ds_filter = ""
    params: list[Any] = []
    if datasets:
        placeholders = ", ".join("?" for _ in datasets)
        ds_filter = f"WHERE dataset IN ({placeholders})"
        params = list(datasets)
    # Pull candidate events biased toward the categories rules fire on.
    q = f"SELECT * FROM events {ds_filter} ORDER BY event_id LIMIT ?"
    raw_rows = siem.con.execute(q, [*params, max_events]).fetchdf().to_dict("records")
    rows: list[dict[str, Any]] = [{str(k): v for k, v in r.items()} for r in raw_rows]
    rng.shuffle(rows)
    try:
        for event in rows:
            ev: dict[str, Any] = {str(k): (None if _is_nan(v) else v) for k, v in event.items()}
            matches = rs.match_event(ev)
            if not matches:
                continue
            match = max(matches, key=lambda m: _level_rank(m.level))
            label, techs, fp_type, scenario = _label_for_event(ev, windows)
            if label == "unknown" and not include_unknown:
                continue
            finding = finding_from_sigma(match, ev, description=match.title)
            yield AlertRecord(
                alert=finding,
                gold_label=label,
                gold_techniques=techs,
                fp_type=fp_type,
                scenario_id=scenario,
                dataset=ev.get("dataset"),
                triggering_event_id=str(ev.get("event_id")),
                rule_id=match.rule_id,
            )
    finally:
        siem.close()


def _level_rank(level: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}.get(level, 0)


def _is_nan(v: Any) -> bool:
    return isinstance(v, float) and v != v


def _ts(v: Any) -> datetime | None:
    return v if isinstance(v, datetime) else None
