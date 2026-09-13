from __future__ import annotations

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from aegis.siem.duckdb import DuckDBSiem, ReadOnlyViolationError
from lab.common.ecs import ARROW_SCHEMA, EcsEvent


def _snapshot(tmp_path):
    events = [
        EcsEvent(
            event_id=f"{i:032x}",
            **{
                "@timestamp": __import__("datetime").datetime(
                    2025, 1, 6, 12, i, tzinfo=__import__("datetime").UTC
                )
            },
            dataset="otrf",
            dataset_ref="r",
            host_name="WS01",
            process_name="rundll32.exe",
            raw="{}",
        )
        for i in range(5)
    ]
    d = tmp_path / "events" / "dataset=otrf"
    d.mkdir(parents=True)
    pq.write_table(
        pa.Table.from_pylist([e.to_row() for e in events], schema=ARROW_SCHEMA), d / "part.parquet"
    )
    return tmp_path


def test_query_and_count(tmp_path) -> None:
    siem = DuckDBSiem(_snapshot(tmp_path))
    try:
        assert siem.count() == 5
        res = siem.query(
            "SELECT host_name, process_name FROM events WHERE process_name = 'rundll32.exe'"
        )
        assert len(res) == 5
        assert res.columns == ["host_name", "process_name"]
    finally:
        siem.close()


def test_get_events_resolves_ids(tmp_path) -> None:
    siem = DuckDBSiem(_snapshot(tmp_path))
    try:
        res = siem.get_events([f"{0:032x}", "not-a-valid-id"])
        assert len(res) == 1
        assert res.rows[0]["event_id"] == f"{0:032x}"
    finally:
        siem.close()


@pytest.mark.parametrize(
    "bad",
    [
        "DELETE FROM events",
        "UPDATE events SET host_name = 'x'",
        "DROP VIEW events",
        "SELECT 1; DROP TABLE events",
        "COPY events TO 'x.csv'",
        "INSTALL httpfs",
        "PRAGMA database_list",
    ],
)
def test_mutating_or_multi_statement_rejected(tmp_path, bad: str) -> None:
    siem = DuckDBSiem(_snapshot(tmp_path))
    try:
        with pytest.raises(ReadOnlyViolationError):
            siem.query(bad)
    finally:
        siem.close()


def test_limit_enforced(tmp_path) -> None:
    siem = DuckDBSiem(_snapshot(tmp_path))
    try:
        res = siem.query("SELECT * FROM events", limit=2)
        assert len(res) == 2
        assert res.truncated
    finally:
        siem.close()
