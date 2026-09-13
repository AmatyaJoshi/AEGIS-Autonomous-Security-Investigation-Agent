from __future__ import annotations

from datetime import UTC, datetime, timedelta

from lab.common.ecs import EcsEvent
from lab.common.sink import ParquetSink
from lab.emulation.ground_truth import GroundTruthTable, GroundTruthWindow
from lab.snapshot import create_snapshot, verify_snapshot


def _seed_data(data_root, n=8):
    t0 = datetime(2025, 1, 6, 12, tzinfo=UTC)
    events = [
        EcsEvent(
            event_id=f"{i:032x}",
            **{"@timestamp": t0 + timedelta(minutes=i)},
            dataset="noise",
            dataset_ref="n",
            host_name="WS01",
            process_name="cmd.exe",
            raw="{}",
        )
        for i in range(n)
    ]
    # a duplicate event_id to prove dedupe
    events.append(events[0])
    ParquetSink(data_root / "parquet").write(events)
    gt = GroundTruthTable(data_root / "ground_truth")
    gt.append(
        [
            GroundTruthWindow(
                window_id="w1",
                scenario_id="s",
                label="fp",
                fp_type="admin_powershell",
                start_ts=t0,
                end_ts=t0 + timedelta(hours=1),
                dataset="noise",
                dataset_ref="n",
                source="noise_generator",
            )
        ]
    )
    return n


def test_snapshot_create_and_verify(tmp_path) -> None:
    n = _seed_data(tmp_path)
    dest = create_snapshot(name="unit", data_root=tmp_path, repo_root=tmp_path, source="parquet")
    assert (dest / "manifest.json").exists()
    report = verify_snapshot(dest)
    assert report["ok"], report["problems"]
    assert report["events_total"] == n  # duplicate deduped


def test_snapshot_detects_tampering(tmp_path) -> None:
    _seed_data(tmp_path)
    dest = create_snapshot(name="unit", data_root=tmp_path, repo_root=tmp_path, source="parquet")
    part = next((dest / "events").rglob("*.parquet"))
    part.write_bytes(part.read_bytes() + b"corruption")
    report = verify_snapshot(dest)
    assert not report["ok"]
    assert any("hash mismatch" in p for p in report["problems"])
