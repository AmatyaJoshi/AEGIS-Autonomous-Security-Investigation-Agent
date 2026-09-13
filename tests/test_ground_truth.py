from __future__ import annotations

from datetime import UTC, datetime, timedelta

from lab.common.ecs import EcsEvent
from lab.emulation.ground_truth import (
    TACTIC_NAMES,
    GroundTruthTable,
    GroundTruthWindow,
    label_events,
)


def _ev(ts: datetime, host: str, user: str | None = None, ref: str = "r") -> EcsEvent:
    return EcsEvent(
        event_id=f"{host}-{ts.isoformat()}",
        **{"@timestamp": ts},
        dataset="otrf",
        dataset_ref=ref,
        host_name=host,
        user_name=user,
        raw="{}",
    )


def test_window_contains_by_time_host_user() -> None:
    t0 = datetime(2025, 1, 6, 12, tzinfo=UTC)
    w = GroundTruthWindow(
        window_id="w1",
        scenario_id="s",
        techniques=["T1003.001"],
        tactics=["credential-access"],
        host="WS01",
        user="adm.patel",
        start_ts=t0,
        end_ts=t0 + timedelta(minutes=5),
        dataset="otrf",
        dataset_ref="r",
        source="test",
    )
    assert w.tactics == ["TA0006"]  # name -> id normalised
    assert w.contains(_ev(t0 + timedelta(minutes=1), "WS01", "adm.patel"))
    assert not w.contains(_ev(t0 + timedelta(minutes=10), "WS01", "adm.patel"))  # out of window
    assert not w.contains(_ev(t0 + timedelta(minutes=1), "DC01", "adm.patel"))  # wrong host


def test_label_events_prefers_specific_window() -> None:
    t0 = datetime(2025, 1, 6, 12, tzinfo=UTC)
    broad = GroundTruthWindow(
        window_id="broad",
        scenario_id="s",
        techniques=["T1059"],
        start_ts=t0,
        end_ts=t0 + timedelta(hours=1),
        dataset="otrf",
        dataset_ref="r",
        source="t",
    )
    specific = GroundTruthWindow(
        window_id="spec",
        scenario_id="s",
        techniques=["T1003.001"],
        host="WS01",
        start_ts=t0,
        end_ts=t0 + timedelta(minutes=5),
        dataset="otrf",
        dataset_ref="r",
        source="t",
    )
    pairs = list(label_events([_ev(t0 + timedelta(minutes=1), "WS01")], [broad, specific]))
    assert pairs[0][1] is specific


def test_table_roundtrip_and_coverage(tmp_path) -> None:
    table = GroundTruthTable(tmp_path)
    t0 = datetime(2025, 1, 6, 12, tzinfo=UTC)
    wins = [
        GroundTruthWindow(
            window_id="w1",
            scenario_id="s",
            label="tp",
            techniques=["T1003.001"],
            tactics=["TA0006"],
            start_ts=t0,
            end_ts=t0 + timedelta(minutes=5),
            dataset="otrf",
            dataset_ref="r",
            source="t",
        ),
        GroundTruthWindow(
            window_id="w2",
            scenario_id="s",
            label="fp",
            fp_type="dev_procdump",
            start_ts=t0,
            end_ts=t0 + timedelta(minutes=5),
            dataset="noise",
            dataset_ref="n",
            source="noise_generator",
        ),
    ]
    assert table.append(wins) == 2
    assert table.append(wins) == 0  # idempotent on window_id
    cov = table.coverage()
    assert cov["tp_windows"] == 1
    assert cov["fp_windows"] == 1
    assert cov["technique_count"] == 1
    assert "dev_procdump" in cov["fp_types"]
    pq = table.to_parquet()
    assert pq.exists()


def test_all_tactics_named() -> None:
    assert TACTIC_NAMES["TA0006"] == "credential-access"
    assert len(TACTIC_NAMES) == 14
