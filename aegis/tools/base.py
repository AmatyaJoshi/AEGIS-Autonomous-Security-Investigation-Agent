"""Tool result envelope shared by every AEGIS tool (SPEC §4).

Every tool returns a ``ToolResult``: a structured ``data`` payload (for deterministic code and the
UI) plus an ``envelope`` string - the ``<data source=...>`` block the LLM sees, in which content is
never treated as an instruction (§9.3). The injection guard runs over the rendered content and any
flags ride along on the result so the graph can force escalation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aegis.security.injection_guard import GuardResult, InjectionFlag, wrap_data


@dataclass
class ToolResult:
    tool: str
    source: str
    data: dict[str, Any]
    envelope: str
    flags: list[InjectionFlag] = field(default_factory=list)
    error: str | None = None

    @property
    def injection_flagged(self) -> bool:
        return bool(self.flags)


def make_result(
    tool: str, source: str, data: dict[str, Any], *, render: str | None = None, guard: bool = True
) -> ToolResult:
    """Build a ToolResult, wrapping ``render`` (or a JSON dump of ``data``) in a <data> envelope."""
    content = render if render is not None else json.dumps(data, indent=2, default=str)
    envelope, guard_result = wrap_data(content, source, guard=guard)
    return ToolResult(
        tool=tool, source=source, data=data, envelope=envelope, flags=guard_result.flags
    )


def error_result(tool: str, source: str, message: str) -> ToolResult:
    envelope, _ = wrap_data(f"error: {message}", source, guard=False)
    return ToolResult(
        tool=tool, source=source, data={"error": message}, envelope=envelope, error=message
    )


def scan_rows(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> GuardResult:
    """Scan selected free-text columns of query rows for injection (used by siem_query)."""
    from aegis.security.injection_guard import scan_fields

    merged: dict[str, str] = {}
    for i, row in enumerate(rows):
        for fld in fields:
            val = row.get(fld)
            if isinstance(val, str) and val:
                merged[f"row{i}.{fld}"] = val
    return scan_fields(merged)
