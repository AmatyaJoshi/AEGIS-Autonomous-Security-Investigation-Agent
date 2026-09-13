"""NL -> SIEM query generation (SPEC §7.2 inference wrapper, used by the siem_query tool).

Two backends behind one interface:

* ``TemplateQueryBuilder`` - deterministic, always-valid query builder that turns an investigative
  intent (English) + typed entities + a time window into a scoped ES|QL or DuckDB query. It is the
  offline default and the fallback for the fine-tuned model, and it is what generates the
  investigative-intent training pairs in §7.2.
* ``FineTunedQueryGenerator`` - loads the Qwen2.5-Coder LoRA via vLLM/transformers when configured
  (``AEGIS_QUERYGEN_MODEL``) and falls back to the template builder on any failure, so the tool
  never emits an unvalidated or empty query.

Both always run their output through :mod:`aegis.siem.validator`; the tool executes only a validated
query. Time/entity scoping is enforced here (the tool), not left to the model (§4).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from aegis.siem.base import TimeWindow
from aegis.siem.validator import ValidationResult, validate

Dialect = Literal["duckdb", "esql"]
EntityType = Literal["host", "user", "ip", "hash", "process", "domain"]

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")

# intent keyword -> (aspect, extra columns, predicate builder key)
_ASPECTS: dict[str, list[str]] = {
    "process": [
        "process",
        "spawn",
        "exec",
        "execut",
        "launch",
        "ran ",
        "run ",
        "created process",
        "child process",
        "command line",
        "commandline",
    ],
    "logon": [
        "logon",
        "login",
        "log on",
        "authentic",
        "sign in",
        "signin",
        "credential use",
        "4624",
        "4625",
        "session",
    ],
    "network": [
        "network",
        "connection",
        "connect",
        "outbound",
        "inbound",
        "beacon",
        "c2",
        "traffic",
        "port",
    ],
    "dns": ["dns", "domain", "resolv", "query name", "lookup domain"],
    "file": ["file", "wrote", "dropped", "created file", "write", "download", "payload"],
    "registry": ["registry", "reg key", "run key", "autorun", "hklm", "hkcu"],
    "service": ["service", "7045", "servicename", "installed service"],
    "powershell": ["powershell", "script block", "scriptblock", "4104", "encoded command"],
    "hash": ["hash", "sha256", "same binary", "file hash"],
    "parent": ["parent", "spawned by", "grandparent", "ancestry", "tree"],
}

_ASPECT_COLUMNS: dict[str, list[str]] = {
    "process": [
        "process_name",
        "process_executable",
        "process_command_line",
        "process_parent_name",
        "process_parent_command_line",
        "user_name",
    ],
    "logon": [
        "event_code",
        "user_name",
        "user_target_name",
        "logon_type",
        "source_ip",
        "event_outcome",
    ],
    "network": [
        "process_name",
        "source_ip",
        "destination_ip",
        "destination_port",
        "network_transport",
    ],
    "dns": ["process_name", "dns_question_name", "user_name"],
    "file": ["process_name", "file_path", "file_name", "user_name"],
    "registry": ["process_name", "registry_path", "registry_data", "user_name"],
    "service": ["service_name", "process_executable", "user_name"],
    "powershell": ["process_name", "script_block_text", "user_name"],
    "hash": ["process_name", "process_executable", "process_hash_sha256", "host_name"],
    "parent": [
        "process_name",
        "process_command_line",
        "process_parent_name",
        "process_parent_command_line",
    ],
    "generic": [
        "event_action",
        "process_name",
        "process_command_line",
        "user_name",
        "source_ip",
        "destination_ip",
    ],
}

_ASPECT_PREDICATE: dict[str, str] = {
    "process": "event_action = 'process_created'",
    "logon": "event_category = 'authentication'",
    "network": "event_action = 'network_connection'",
    "dns": "event_action = 'dns_query'",
    "file": "event_category = 'file'",
    "registry": "event_category = 'registry'",
    "service": "event_action = 'service_installed'",
    "powershell": "event_action IN ('script_block_logged','module_logged')",
    "hash": "process_hash_sha256 IS NOT NULL",
    "parent": "event_action = 'process_created'",
    "generic": "",
}


@dataclass
class Entity:
    value: str
    type: EntityType

    @staticmethod
    def classify(value: str, known_hosts: set[str] | None = None) -> Entity:
        v = value.strip()
        try:
            ipaddress.ip_address(v)
            return Entity(v, "ip")
        except ValueError:
            pass
        if _HASH_RE.match(v):
            return Entity(v.lower(), "hash")
        if (
            "." in v
            and not v.replace(".", "").isdigit()
            and "\\" not in v
            and " " not in v
            and v.count(".") >= 1
            and any(c.isalpha() for c in v.rsplit(".", 1)[-1])
        ):
            # dotted, alpha TLD -> domain (unless it's a known host FQDN)
            if known_hosts and v.split(".")[0].upper() in known_hosts:
                return Entity(v.split(".")[0].upper(), "host")
            return Entity(v.lower(), "domain")
        if known_hosts and v.upper() in known_hosts:
            return Entity(v.upper(), "host")
        if v.endswith(".exe") or "\\" in v:
            return Entity(v, "process")
        # Heuristic: short all-caps token -> host; contains a dot/space or lowercase -> user
        if v.isupper() and " " not in v and len(v) <= 20:
            return Entity(v, "host")
        return Entity(v, "user")


@dataclass
class QuerySpec:
    intent: str
    entities: list[Entity]
    window: TimeWindow
    aspect: str = "generic"
    limit: int = 200
    extra_columns: list[str] = field(default_factory=list)


def detect_aspect(intent: str) -> str:
    low = intent.lower()
    best = "generic"
    for aspect, kws in _ASPECTS.items():
        if any(kw in low for kw in kws):
            best = aspect
            break
    return best


_ENTITY_COLUMNS: dict[EntityType, list[str]] = {
    "host": ["host_name"],
    "user": ["user_name", "user_target_name"],
    "ip": ["source_ip", "destination_ip"],
    "hash": ["process_hash_sha256", "process_hash_md5", "file_hash_sha256"],
    "process": ["process_name", "process_executable"],
    "domain": ["dns_question_name"],
}


class TemplateQueryBuilder:
    """Builds a scoped, always-valid query from a QuerySpec. Deterministic."""

    def build(self, spec: QuerySpec, dialect: Dialect = "duckdb") -> str:
        cols = list(
            dict.fromkeys(
                [
                    "@timestamp",
                    "event_id",
                    "host_name",
                    "event_action",
                    *_ASPECT_COLUMNS.get(spec.aspect, _ASPECT_COLUMNS["generic"]),
                    *spec.extra_columns,
                ]
            )
        )
        entity_clause = self._entity_clause(spec.entities, dialect)
        time_clause = self._time_clause(spec.window, dialect)
        aspect_pred = _ASPECT_PREDICATE.get(spec.aspect, "")
        where = [time_clause]
        if entity_clause:
            where.append(entity_clause)
        if aspect_pred:
            where.append(aspect_pred)
        where_sql = " AND ".join(f"({w})" for w in where)
        limit = min(spec.limit, 500)
        if dialect == "duckdb":
            col_sql = ", ".join(f'"{c}"' if c.startswith("@") else c for c in cols)
            return (
                f"SELECT {col_sql} FROM events WHERE {where_sql} "
                f'ORDER BY "@timestamp" LIMIT {limit}'
            )
        # ES|QL
        keep = ", ".join(_to_ecs(c) for c in cols)
        return (
            f"FROM {ES_INDEX} | WHERE {where_sql} | KEEP {keep} | SORT @timestamp | LIMIT {limit}"
        )

    def _entity_clause(self, entities: list[Entity], dialect: Dialect) -> str:
        ors: list[str] = []
        for e in entities:
            for col in _ENTITY_COLUMNS[e.type]:
                val = e.value.replace("'", "''")
                column = col if dialect == "duckdb" else _to_ecs(col)
                if e.type in ("process", "domain"):
                    ors.append(
                        f"{column} LIKE '%{val}%'"
                        if dialect == "duckdb"
                        else f'{column} LIKE "*{val}*"'
                    )
                else:
                    ors.append(f"{column} = '{val}'")
        return " OR ".join(ors)

    def _time_clause(self, window: TimeWindow, dialect: Dialect) -> str:
        start = _iso(window.start)
        end = _iso(window.end)
        if dialect == "duckdb":
            return f"\"@timestamp\" BETWEEN TIMESTAMP '{start}' AND TIMESTAMP '{end}'"
        return f'@timestamp >= "{start}" AND @timestamp <= "{end}"'


ES_INDEX = "logs-*"

_ECS_MAP = {
    "host_name": "host.name",
    "user_name": "user.name",
    "user_target_name": "user.target.name",
    "process_name": "process.name",
    "process_executable": "process.executable",
    "process_command_line": "process.command_line",
    "process_parent_name": "process.parent.name",
    "process_parent_command_line": "process.parent.command_line",
    "source_ip": "source.ip",
    "destination_ip": "destination.ip",
    "destination_port": "destination.port",
    "network_transport": "network.transport",
    "dns_question_name": "dns.question.name",
    "file_path": "file.path",
    "file_name": "file.name",
    "registry_path": "registry.path",
    "registry_data": "registry.data.strings",
    "service_name": "service.name",
    "script_block_text": "powershell.file.script_block_text",
    "process_hash_sha256": "process.hash.sha256",
    "process_hash_md5": "process.hash.md5",
    "file_hash_sha256": "file.hash.sha256",
    "event_code": "event.code",
    "event_action": "event.action",
    "event_category": "event.category",
    "event_outcome": "event.outcome",
    "logon_type": "winlog.logon.type",
    "event_id": "event.id",
}


def _to_ecs(col: str) -> str:
    if col.startswith("@"):
        return col
    return _ECS_MAP.get(col, col)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class GeneratedQuery:
    query: str
    dialect: Dialect
    backend: str  # "template" | "finetuned"
    validation: ValidationResult
    spec: QuerySpec


class QueryGenerator:
    """Front door used by the siem_query tool. Fine-tuned model if available, else template."""

    def __init__(self, model: object | None = None, known_hosts: set[str] | None = None) -> None:
        self.builder = TemplateQueryBuilder()
        self.model = model  # FineTunedQueryGenerator or None
        self.known_hosts = known_hosts or set()

    def generate(
        self,
        intent: str,
        entities: list[str],
        window: TimeWindow,
        dialect: Dialect = "duckdb",
        limit: int = 200,
    ) -> GeneratedQuery:
        typed = [Entity.classify(e, self.known_hosts) for e in entities if e and e.strip()]
        spec = QuerySpec(
            intent=intent, entities=typed, window=window, aspect=detect_aspect(intent), limit=limit
        )
        backend = "template"
        query = ""
        if self.model is not None:
            try:
                query = self.model.generate(spec, dialect)  # type: ignore[attr-defined]
                backend = "finetuned"
            except Exception:
                query = ""
        if not query:
            query = self.builder.build(spec, dialect)
            backend = "template"
        vr = validate(query, dialect)
        if not vr.ok:
            # A fine-tuned model may produce an unscoped query; fall back to the safe builder.
            query = self.builder.build(spec, dialect)
            backend = "template"
            vr = validate(query, dialect)
        return GeneratedQuery(
            query=vr.query or query, dialect=dialect, backend=backend, validation=vr, spec=spec
        )
