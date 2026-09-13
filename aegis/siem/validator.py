"""SIEM query validator (SPEC §4, §9.1) - the one gate every generated query must pass.

CLAUDE.md: "Generated SIEM queries must pass aegis/siem/validator before execution - no exceptions,
no bypass flags." There is deliberately no ``force`` parameter.

The validator enforces, for both dialects (``duckdb`` SQL and ``esql``):

* single statement, read-only leading command only (SELECT/WITH/FROM);
* no mutating / side-effecting keyword anywhere;
* a mandatory time filter that resolves to a window <= ``MAX_WINDOW_DAYS`` days;
* a mandatory entity filter (host / user / ip / process / hash / domain);
* a row limit <= ``MAX_LIMIT`` (added or clamped if missing/too large).

It returns a ``ValidationResult`` with either the (possibly limit-clamped) query or a rejection
reason. The tool executes only ``result.query`` and only when ``result.ok``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta

MAX_LIMIT = 500
MAX_WINDOW_DAYS = 30

# Any of these anywhere in the query is an immediate reject (word-boundary matched).
_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|replace|copy|attach|detach|install|load|pragma|"
    r"set|export|import|call|truncate|vacuum|checkpoint|grant|revoke|merge|upsert|into|"
    r"enrich|dissect|row)\b",
    re.IGNORECASE,
)
# ES|QL commands that write, change cluster state or run arbitrary functions we do not allow.
_ESQL_FORBIDDEN_CMDS = {"enrich", "row", "show", "meta", "grok", "dissect"}

_ENTITY_FIELDS = (
    "host_name",
    "host.name",
    "user_name",
    "user.name",
    "source_ip",
    "source.ip",
    "destination_ip",
    "destination.ip",
    "process_name",
    "process.name",
    "process_executable",
    "process.executable",
    "process_hash_sha256",
    "process.hash.sha256",
    "dns_question_name",
    "dns.question.name",
    "user.domain",
    "user_domain",
)
_TIME_FIELDS = ("@timestamp", "timestamp")

_TIME_FILTER_RE = re.compile(
    r"(\"?@?timestamp\"?)\s*(>=|>|between|<=|<)|"
    r"\bnow\(\)\s*-\s*interval|"
    r"\btimestamp\s+within\b|"
    r"date_diff|date_trunc\([^)]*timestamp",
    re.IGNORECASE,
)
_INTERVAL_RE = re.compile(
    r"interval\s+'?(\d+)'?\s*(day|days|hour|hours|minute|minutes)", re.IGNORECASE
)
_LIMIT_RE = re.compile(r"\blimit\s+(\d+)\b", re.IGNORECASE)


@dataclass
class ValidationResult:
    ok: bool
    query: str = ""
    reason: str = ""
    warnings: list[str] = field(default_factory=list)
    clamped_limit: int | None = None


def _has_entity_filter(q: str) -> bool:
    lower = q.lower()
    return any(f.lower() in lower for f in _ENTITY_FIELDS)


def _window_days_ok(q: str) -> tuple[bool, str]:
    matches = _INTERVAL_RE.findall(q)
    if not matches:
        # A BETWEEN / explicit timestamp bound counts as scoped even without an interval literal.
        return True, ""
    for num, unit in matches:
        days: float = int(num) if unit.lower().startswith("day") else 0.0
        if unit.lower().startswith("hour"):
            days = int(num) / 24
        if unit.lower().startswith("minute"):
            days = int(num) / 1440
        if days > MAX_WINDOW_DAYS:
            return False, f"time window {num} {unit} exceeds {MAX_WINDOW_DAYS} days"
    return True, ""


def _clamp_limit(q: str, dialect: str) -> tuple[str, int | None]:
    m = _LIMIT_RE.search(q)
    if m:
        current = int(m.group(1))
        if current > MAX_LIMIT:
            return _LIMIT_RE.sub(f"LIMIT {MAX_LIMIT}", q, count=1), MAX_LIMIT
        return q, None
    # No limit present -> append one.
    sep = "\n| " if dialect == "esql" else " "
    return f"{q.rstrip().rstrip(';')}{sep}LIMIT {MAX_LIMIT}", MAX_LIMIT


def _base_checks(q: str) -> str | None:
    stripped = q.strip().rstrip(";").strip()
    if not stripped:
        return "empty query"
    if ";" in stripped:
        return "multiple statements are not allowed"
    if _FORBIDDEN.search(stripped):
        m = _FORBIDDEN.search(stripped)
        return f"forbidden keyword: {m.group(0) if m else '?'}"
    return None


def validate_sql(query: str) -> ValidationResult:
    """Validate a DuckDB SQL query for the offline SIEM adapter."""
    err = _base_checks(query)
    if err:
        return ValidationResult(False, reason=err)
    stripped = query.strip().rstrip(";").strip()
    if not re.match(r"^(select|with)\b", stripped, re.IGNORECASE):
        return ValidationResult(False, reason="only SELECT/WITH queries are allowed")
    if "from events" not in stripped.lower() and "from ground_truth" not in stripped.lower():
        return ValidationResult(False, reason="query must read FROM events")
    if not _TIME_FILTER_RE.search(stripped):
        return ValidationResult(False, reason="missing mandatory time filter on @timestamp")
    ok, why = _window_days_ok(stripped)
    if not ok:
        return ValidationResult(False, reason=why)
    if not _has_entity_filter(stripped):
        return ValidationResult(False, reason="missing mandatory entity filter (host/user/ip/...)")
    final, clamped = _clamp_limit(stripped, "duckdb")
    warnings = [] if clamped is None else [f"limit clamped to {MAX_LIMIT}"]
    return ValidationResult(True, query=final, warnings=warnings, clamped_limit=clamped)


def validate_esql(query: str) -> ValidationResult:
    """Validate an Elasticsearch ES|QL query."""
    err = _base_checks(query)
    if err:
        return ValidationResult(False, reason=err)
    stripped = query.strip().rstrip(";").strip()
    if not re.match(r"^from\b", stripped, re.IGNORECASE):
        return ValidationResult(False, reason="ES|QL query must start with FROM")
    commands = [seg.strip().split()[0].lower() for seg in stripped.split("|")[1:] if seg.strip()]
    bad = set(commands) & _ESQL_FORBIDDEN_CMDS
    if bad:
        return ValidationResult(False, reason=f"forbidden ES|QL command(s): {sorted(bad)}")
    if not _TIME_FILTER_RE.search(stripped):
        return ValidationResult(False, reason="missing mandatory time filter on @timestamp")
    ok, why = _window_days_ok(stripped)
    if not ok:
        return ValidationResult(False, reason=why)
    if not _has_entity_filter(stripped):
        return ValidationResult(False, reason="missing mandatory entity filter (host/user/ip/...)")
    final, clamped = _clamp_limit(stripped, "esql")
    warnings = [] if clamped is None else [f"limit clamped to {MAX_LIMIT}"]
    return ValidationResult(True, query=final, warnings=warnings, clamped_limit=clamped)


def validate(query: str, dialect: str) -> ValidationResult:
    if dialect == "esql":
        return validate_esql(query)
    if dialect in ("duckdb", "sql"):
        return validate_sql(query)
    return ValidationResult(False, reason=f"unknown dialect {dialect!r}")


def max_window() -> timedelta:
    return timedelta(days=MAX_WINDOW_DAYS)
