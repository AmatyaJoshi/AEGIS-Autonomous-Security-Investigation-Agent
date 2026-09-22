"""Evorozen Neural Pulse client (Phase 1). Metadata only - see SECURITY.md "Pulse boundary".

Contract verified against https://pulse.evorozen.com/docs on 2026-09-22:

    POST https://pulse.evorozen.com/api/neural
    Authorization: Bearer <API_KEY>
    {"action_type": "...", "prompt": "...", "data_payload": {...}}

Documented ``action_type`` values: ``create_schema``, ``insert_data``, ``select_data``,
``update_data``, ``delete_data``, ``chat``. The brief also named ``bulk_insert``, ``upsert_data``,
``count`` and ``analytics``; those are **not** in the docs, so this client composes them from the
documented verbs (``insert_many`` loops ``insert_data``; ``upsert`` is select + update-or-insert;
``count`` is select + ``len``; ``analytics`` is ``chat`` with a prompt). ``delete_data`` is
deliberately not exposed: AEGIS never deletes memory.

Every call passes the outbound allow-list, a hard per-day call budget
(``BUDGET_PULSE_CALLS_PER_DAY``), a short timeout and bounded retries. Any failure raises
:class:`PulseUnavailableError`; the store layer turns that into the local fallback.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from aegis.llm.budget import BudgetGuard, DegradedError, check_outbound

log = logging.getLogger("aegis.memory.pulse")

DEFAULT_BASE_URL = "https://pulse.evorozen.com"
ENDPOINT = "/api/neural"


class PulseUnavailableError(RuntimeError):
    """Pulse could not be reached, refused the request, or the call budget is exhausted."""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class PulseClient:
    api_key: str | None = field(default_factory=lambda: os.environ.get("AEGIS_PULSE_API_KEY"))
    base_url: str = field(
        default_factory=lambda: os.environ.get("AEGIS_PULSE_BASE_URL", DEFAULT_BASE_URL)
    )
    timeout_s: float = 2.0  # network-off fallback must resolve within 2 s (Phase 1 acceptance)
    retries: int = 2
    backoff_s: float = 0.2
    calls_per_day: int = field(default_factory=lambda: _env_int("BUDGET_PULSE_CALLS_PER_DAY", 40))
    guard: BudgetGuard | None = None
    transport: httpx.BaseTransport | None = None  # tests inject httpx.MockTransport
    calls: int = 0

    def __post_init__(self) -> None:
        if self.guard is None:
            self.guard = BudgetGuard(
                external_calls_per_day=self.calls_per_day,
                state_path=__import__("pathlib").Path(os.environ.get("AEGIS_DATA_ROOT", "data"))
                / "pulse_budget.json",
            )

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    # ------------------------------------------------------------------ transport
    def _request(self, action_type: str, **payload: Any) -> dict[str, Any]:
        if not self.api_key:
            raise PulseUnavailableError("AEGIS_PULSE_API_KEY is not set")
        assert self.guard is not None
        url = f"{self.base_url.rstrip('/')}{ENDPOINT}"
        check_outbound(url)
        try:
            self.guard.check("external")
        except DegradedError as e:
            raise PulseUnavailableError(f"Pulse call budget exhausted: {e}") from e
        body: dict[str, Any] = {"action_type": action_type, **payload}
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        last: str = ""
        for attempt in range(self.retries + 1):
            try:
                with httpx.Client(timeout=self.timeout_s, transport=self.transport) as c:
                    r = c.post(url, json=body, headers=headers)
                self.calls += 1
                self.guard.record(kind="external")
                if r.status_code == 401 or r.status_code == 403:
                    raise PulseUnavailableError(f"Pulse rejected the key (HTTP {r.status_code})")
                if r.status_code == 429 or r.status_code >= 500:
                    last = f"HTTP {r.status_code}"
                    if attempt < self.retries:
                        time.sleep(self.backoff_s * (2**attempt))
                        continue
                    raise PulseUnavailableError(f"Pulse {last} after {self.retries + 1} attempts")
                if r.status_code >= 400:
                    raise PulseUnavailableError(f"Pulse HTTP {r.status_code}: {r.text[:200]}")
                data = r.json()
                if not isinstance(data, dict):
                    raise PulseUnavailableError("Pulse returned a non-object body")
                return data
            except httpx.HTTPError as e:
                last = f"{type(e).__name__}"
                if attempt < self.retries:
                    time.sleep(self.backoff_s * (2**attempt))
                    continue
                raise PulseUnavailableError(f"Pulse unreachable: {last}") from e
        raise PulseUnavailableError(last or "unknown")  # pragma: no cover

    # ------------------------------------------------------------------ documented verbs
    def create_schema(self, tables: list[dict[str, Any]], prompt: str = "") -> dict[str, Any]:
        return self._request(
            "create_schema",
            prompt=prompt or "Register AEGIS case-memory tables",
            data_payload={"tables": tables},
        )

    def insert(self, table: str, record: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "insert_data",
            prompt=f"Insert into {table}",
            data_payload={"table": table, "record": record},
        )

    def select(self, table: str, where: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"table": table}
        if where:
            payload["where"] = where
        data = self._request("select_data", data_payload=payload)
        rows = data.get("data") or data.get("rows") or []
        return [r for r in rows if isinstance(r, dict)]

    def update(self, table: str, where: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "update_data",
            data_payload={"table": table, "where": where, "changes": changes},
        )

    def chat(self, prompt: str) -> str:
        data = self._request("chat", prompt=prompt)
        return str(data.get("response") or data.get("answer") or "")

    # ------------------------------------------------------------------ composed verbs
    def insert_many(self, table: str, records: list[dict[str, Any]]) -> int:
        """The docs have no bulk verb; one ``insert_data`` per record, stopping at the budget."""
        n = 0
        for rec in records:
            self.insert(table, rec)
            n += 1
        return n

    def upsert(self, table: str, key_field: str, record: dict[str, Any]) -> str:
        """Select by key then update or insert. Returns ``"updated"`` or ``"inserted"``."""
        existing = self.select(table, {key_field: record[key_field]})
        if existing:
            self.update(table, {key_field: record[key_field]}, record)
            return "updated"
        self.insert(table, record)
        return "inserted"

    def count(self, table: str, where: dict[str, Any] | None = None) -> int:
        return len(self.select(table, where))

    def analytics(self, question: str, table: str) -> str:
        return self.chat(f"Using only the table {table}: {question}")
