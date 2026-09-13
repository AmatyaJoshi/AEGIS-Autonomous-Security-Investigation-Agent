from __future__ import annotations

import pytest
from aegis.siem.validator import MAX_LIMIT, validate_esql, validate_sql


@pytest.mark.parametrize(
    "q",
    [
        "DELETE FROM events WHERE host_name='x'",
        "SELECT * FROM events; DROP TABLE events",
        "UPDATE events SET x=1",
        "SELECT * FROM events",  # no time filter
        'SELECT * FROM events WHERE "@timestamp" > now()',  # no entity filter
    ],
)
def test_sql_rejects_bad(q: str) -> None:
    assert not validate_sql(q).ok


def test_sql_accepts_scoped_and_clamps_limit() -> None:
    q = (
        "SELECT event_id FROM events WHERE \"@timestamp\" BETWEEN TIMESTAMP '2025-01-01' "
        "AND TIMESTAMP '2025-01-02' AND host_name = 'WS01' LIMIT 9000"
    )
    r = validate_sql(q)
    assert r.ok
    assert f"LIMIT {MAX_LIMIT}" in r.query
    assert r.clamped_limit == MAX_LIMIT


def test_sql_appends_limit_when_missing() -> None:
    q = (
        "SELECT event_id FROM events WHERE \"@timestamp\" >= TIMESTAMP '2025-01-01' "
        "AND user_name = 'adm.patel'"
    )
    r = validate_sql(q)
    assert r.ok and f"LIMIT {MAX_LIMIT}" in r.query


def test_sql_rejects_window_over_30_days() -> None:
    q = (
        'SELECT event_id FROM events WHERE "@timestamp" > now() - interval 60 day '
        "AND host_name = 'WS01'"
    )
    assert not validate_sql(q).ok


def test_esql_requires_from_and_scoping() -> None:
    assert not validate_esql('WHERE host.name == "x"').ok
    ok = validate_esql(
        'FROM logs-* | WHERE @timestamp >= "2025-01-01" AND host.name == "WS01" | LIMIT 100'
    )
    assert ok.ok


def test_esql_rejects_forbidden_command() -> None:
    q = 'FROM logs-* | WHERE @timestamp >= "2025-01-01" AND host.name == "WS01" | ENRICH policy'
    assert not validate_esql(q).ok
