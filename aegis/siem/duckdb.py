"""DuckDB-over-Parquet SIEM adapter for ``--offline`` mode (SPEC §2.1, §8.5).

Opens a snapshot directory (see ``lab/snapshot.py``) read-only and exposes the event table as
``events`` plus ``ground_truth`` and ``rules`` views. Only ``SELECT``/``WITH`` statements are
accepted; the connection itself is opened with ``read_only`` semantics (in-memory DB, Parquet files
are never modified). The full query validator (allow-list, mandatory time and entity scoping) is
Phase 2; this adapter enforces the minimum invariant that nothing can mutate.
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import duckdb

from aegis.siem.base import QueryResult

_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|copy|attach|detach|install|load|pragma|set|"
    r"export|import|call|truncate|vacuum|checkpoint)\b",
    re.IGNORECASE,
)


class ReadOnlyViolationError(PermissionError):
    pass


class DuckDBSiem:
    dialect = "duckdb"

    def __init__(self, snapshot_dir: Path) -> None:
        self.snapshot_dir = Path(snapshot_dir)
        events = self.snapshot_dir / "events"
        if not events.exists():
            raise FileNotFoundError(f"no events/ under {self.snapshot_dir}")
        self.con = duckdb.connect(database=":memory:")
        glob = (events / "**" / "*.parquet").as_posix()
        self.con.execute(
            f"CREATE VIEW events AS SELECT * FROM read_parquet('{glob}', hive_partitioning=true, "
            "union_by_name=true)"
        )
        gt = self.snapshot_dir / "ground_truth" / "windows.parquet"
        if gt.exists():
            self.con.execute(
                f"CREATE VIEW ground_truth AS SELECT * FROM read_parquet('{gt.as_posix()}')"
            )
        rules = self.snapshot_dir / "rules" / "sigma_pack.jsonl"
        if rules.exists():
            self.con.execute(
                f"CREATE VIEW rules AS SELECT * FROM read_json_auto('{rules.as_posix()}', "
                "format='newline_delimited', maximum_object_size=4194304)"
            )

    @staticmethod
    def assert_read_only(query: str) -> None:
        stripped = query.strip().rstrip(";").strip()
        if ";" in stripped:
            raise ReadOnlyViolationError("multiple statements are not allowed")
        if not re.match(r"^(select|with|describe|show|summarize)\b", stripped, re.IGNORECASE):
            raise ReadOnlyViolationError("only SELECT/WITH queries are allowed")
        if _FORBIDDEN.search(stripped):
            raise ReadOnlyViolationError("query contains a forbidden keyword")

    def query(self, query: str, *, limit: int = 500) -> QueryResult:
        self.assert_read_only(query)
        q = query.strip().rstrip(";")
        wrapped = f"SELECT * FROM ({q}) AS q LIMIT {int(limit) + 1}"
        t0 = time.perf_counter()
        cur = self.con.execute(wrapped)
        cols = [d[0] for d in cur.description or []]
        raw = cur.fetchall()
        took = (time.perf_counter() - t0) * 1000
        truncated = len(raw) > limit
        rows = [dict(zip(cols, r, strict=True)) for r in raw[:limit]]
        return QueryResult(query=q, columns=cols, rows=rows, took_ms=took, truncated=truncated)

    def get_events(self, event_ids: Sequence[str]) -> QueryResult:
        ids = [i for i in event_ids if re.fullmatch(r"[0-9a-f]{32}", i)]
        if not ids:
            return QueryResult(query="", columns=[], rows=[], took_ms=0.0)
        placeholders = ", ".join("?" for _ in ids)
        t0 = time.perf_counter()
        cur = self.con.execute(f"SELECT * FROM events WHERE event_id IN ({placeholders})", ids)
        cols = [d[0] for d in cur.description or []]
        rows = [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]
        return QueryResult(
            query="get_events", columns=cols, rows=rows, took_ms=(time.perf_counter() - t0) * 1000
        )

    def count(self) -> int:
        return int(self.con.execute("SELECT count(*) FROM events").fetchone()[0])  # type: ignore[index]

    def stats(self) -> dict[str, Any]:
        rows = self.con.execute(
            'SELECT dataset, count(*) AS n, min("@timestamp") AS first_ts, '
            'max("@timestamp") AS last_ts, count(DISTINCT host_name) AS hosts '
            "FROM events GROUP BY dataset ORDER BY dataset"
        ).fetchall()
        return {
            r[0]: {"events": r[1], "first_ts": str(r[2]), "last_ts": str(r[3]), "hosts": r[4]}
            for r in rows
        }

    def close(self) -> None:
        self.con.close()
