"""SIEM adapter interface (read-only by construction).

Phase 1 ships the interface and the DuckDB-over-Parquet adapter used by ``--offline`` mode and the
snapshot verifier. Elasticsearch (ES|QL) and Splunk (SPL) adapters, plus the mandatory query
validator (§4), arrive in Phase 2. No adapter exposes write, update or delete operations - there is
nothing to bypass.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class QueryResult:
    query: str
    columns: list[str]
    rows: list[dict[str, Any]]
    took_ms: float
    truncated: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.rows)


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.end < self.start:
            raise ValueError("TimeWindow end before start")


class SiemAdapter(Protocol):
    """Read-only access to the log store."""

    dialect: str  # "esql" | "spl" | "duckdb"

    def query(self, query: str, *, limit: int = 500) -> QueryResult: ...

    def get_events(self, event_ids: Sequence[str]) -> QueryResult:
        """Resolve EvidenceRef ids to documents (must exist -> otherwise the claim is invalid)."""
        ...

    def count(self) -> int: ...
