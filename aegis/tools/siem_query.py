"""siem_query tool (SPEC §4): NL intent -> validated, scoped query -> execute -> rows.

Flow (scoping enforced by the tool, not the model):
1. ``QueryGenerator`` turns intent + entities + window into a query (fine-tuned model or template).
2. The query is validated by :mod:`aegis.siem.validator` (already done inside the generator; the
   result carries the validated string). An invalid query is refused - there is no bypass.
3. The validated query runs against the read-only SIEM adapter.
4. Result rows are scanned for injection (free-text columns) and wrapped in a ``<data>`` envelope.

The returned rows carry ``event_id`` so the evidence node can build ``EvidenceRef``s that resolve to
real documents.
"""

from __future__ import annotations

from typing import Any

from aegis.models.query_gen import Dialect, QueryGenerator
from aegis.siem.base import SiemAdapter, TimeWindow
from aegis.tools.base import ToolResult, error_result, make_result, scan_rows

_INJECTION_SCAN_COLUMNS = (
    "process_command_line",
    "process_parent_command_line",
    "script_block_text",
    "message",
    "file_path",
    "dns_question_name",
)


def siem_query(
    intent: str,
    entities: list[str],
    window: TimeWindow,
    *,
    siem: SiemAdapter,
    generator: QueryGenerator | None = None,
    limit: int = 200,
) -> ToolResult:
    generator = generator or QueryGenerator()
    dialect: Dialect = "esql" if siem.dialect == "esql" else "duckdb"
    gen = generator.generate(intent, entities, window, dialect=dialect, limit=limit)
    if not gen.validation.ok:
        return error_result("siem_query", "siem", f"query rejected: {gen.validation.reason}")
    try:
        result = siem.query(gen.query, limit=min(limit, 500))
    except Exception as e:
        return error_result("siem_query", "siem", f"execution failed: {type(e).__name__}: {e}")

    guard = scan_rows(result.rows, _INJECTION_SCAN_COLUMNS)
    data: dict[str, Any] = {
        "intent": intent,
        "query": gen.query,
        "dialect": dialect,
        "backend": gen.backend,
        "aspect": gen.spec.aspect,
        "entities": [{"value": e.value, "type": e.type} for e in gen.spec.entities],
        "row_count": len(result.rows),
        "truncated": result.truncated,
        "took_ms": round(result.took_ms, 1),
        "warnings": gen.validation.warnings,
        "rows": result.rows,
    }
    render = _render(gen.query, result.columns, result.rows)
    tr = make_result("siem_query", "siem", data, render=render, guard=True)
    tr.flags.extend(guard.flags)
    return tr


def _render(query: str, columns: list[str], rows: list[dict[str, Any]], max_rows: int = 25) -> str:
    lines = [f"query: {query}", f"rows: {len(rows)}", ""]
    for r in rows[:max_rows]:
        parts = []
        for c in columns:
            v = r.get(c)
            if v is not None and str(v) != "":
                parts.append(f"{c}={v}")
        lines.append(" | ".join(parts))
    if len(rows) > max_rows:
        lines.append(f"... ({len(rows) - max_rows} more rows)")
    return "\n".join(lines)
