"""Event sinks: Parquet (offline / snapshot) and Elasticsearch (lab SIEM).

Loaders yield ``EcsEvent`` objects; a sink persists them. Both sinks are idempotent on ``event_id``
(Parquet dedupes at snapshot time, Elasticsearch uses ``_id = event_id``).

Guardrail §9.1: ``ElasticSink`` is the ONLY place the *writer* credential is used, and it lives in
``lab/`` - never in ``aegis/tools``. The agent's SIEM adapter (``aegis/siem``) is read-only.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol

import pyarrow as pa
import pyarrow.parquet as pq
from aegis.config import ElasticSettings
from lab.common.ecs import ARROW_SCHEMA, EcsEvent, batched

log = logging.getLogger(__name__)


class EventSink(Protocol):
    def write(self, events: Iterable[EcsEvent]) -> int: ...

    def close(self) -> None: ...


class ParquetSink:
    """Writes ``data/parquet/events/dataset=<ds>/<dataset_ref>-<n>.parquet`` files."""

    def __init__(self, root: Path, rows_per_file: int = 50_000) -> None:
        self.root = root
        self.rows_per_file = rows_per_file
        self.files_written: list[Path] = []
        self.rows_written = 0

    def write(self, events: Iterable[EcsEvent]) -> int:
        n = 0
        for batch in batched(events, self.rows_per_file):
            table = pa.Table.from_pylist([e.to_row() for e in batch], schema=ARROW_SCHEMA)
            ds = batch[0].dataset
            ref = _safe(batch[0].dataset_ref)
            out_dir = self.root / "events" / f"dataset={ds}"
            out_dir.mkdir(parents=True, exist_ok=True)
            idx = sum(1 for p in out_dir.glob(f"{ref}-*.parquet"))
            path = out_dir / f"{ref}-{idx:04d}.parquet"
            pq.write_table(table, path, compression="zstd")
            self.files_written.append(path)
            n += table.num_rows
        self.rows_written += n
        return n

    def close(self) -> None:
        return None


class ElasticSink:
    """Bulk-indexes into ``<prefix>-events-<dataset>`` with ``_id = event_id``."""

    def __init__(self, settings: ElasticSettings, batch_size: int = 2_000) -> None:
        from elasticsearch import Elasticsearch

        kwargs: dict[str, Any] = {"request_timeout": settings.request_timeout_s}
        if settings.writer_api_key is not None:
            kwargs["api_key"] = settings.writer_api_key.get_secret_value()
        elif settings.username and settings.password is not None:
            kwargs["basic_auth"] = (settings.username, settings.password.get_secret_value())
        self.client = Elasticsearch(settings.url, verify_certs=settings.verify_certs, **kwargs)
        self.prefix = settings.index_prefix
        self.batch_size = batch_size
        self._ensured: set[str] = set()
        self.rows_written = 0

    def index_for(self, dataset: str) -> str:
        return f"{self.prefix}-events-{dataset}"

    def _ensure_index(self, name: str) -> None:
        if name in self._ensured:
            return
        if not self.client.indices.exists(index=name):
            self.client.indices.create(index=name, body=INDEX_TEMPLATE)
        self._ensured.add(name)

    def write(self, events: Iterable[EcsEvent]) -> int:
        from elasticsearch.helpers import bulk

        n = 0
        for batch in batched(events, self.batch_size):
            actions = []
            for e in batch:
                idx = self.index_for(e.dataset)
                self._ensure_index(idx)
                actions.append({"_index": idx, "_id": e.event_id, "_source": e.to_es_doc()})
            ok, errors = bulk(self.client, actions, raise_on_error=False, stats_only=False)
            if errors:
                log.warning("bulk: %d errors (first: %s)", len(errors), errors[0])
            n += int(ok)
        self.rows_written += n
        return n

    def close(self) -> None:
        self.client.close()


class MultiSink:
    def __init__(self, *sinks: EventSink) -> None:
        self.sinks = sinks

    def write(self, events: Iterable[EcsEvent]) -> int:
        buf = list(events)
        return max(s.write(buf) for s in self.sinks) if buf else 0

    def close(self) -> None:
        for s in self.sinks:
            s.close()


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:80]


# ECS-compatible mapping. Dynamic templates keep unknown keys searchable as keywords.
INDEX_TEMPLATE: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
        "analysis": {"normalizer": {"lowercase": {"type": "custom", "filter": ["lowercase"]}}},
    },
    "mappings": {
        "dynamic_templates": [
            {
                "strings_as_keywords": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "keyword", "ignore_above": 8192},
                }
            }
        ],
        "properties": {
            "@timestamp": {"type": "date"},
            "message": {"type": "text"},
            "event": {
                "properties": {
                    "id": {"type": "keyword"},
                    "code": {"type": "keyword"},
                    "dataset": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "action": {"type": "keyword"},
                }
            },
            "host": {"properties": {"name": {"type": "keyword"}}},
            "user": {"properties": {"name": {"type": "keyword"}, "domain": {"type": "keyword"}}},
            "process": {
                "properties": {
                    "name": {"type": "keyword"},
                    "pid": {"type": "long"},
                    "executable": {
                        "type": "keyword",
                        "fields": {"caseless": {"type": "keyword", "normalizer": "lowercase"}},
                    },
                    "command_line": {"type": "wildcard", "fields": {"text": {"type": "text"}}},
                    "parent": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "pid": {"type": "long"},
                            "executable": {"type": "keyword"},
                            "command_line": {"type": "wildcard"},
                        }
                    },
                }
            },
            "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
            "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
            "network": {"properties": {"bytes": {"type": "long"}}},
            "powershell": {
                "properties": {"file": {"properties": {"script_block_text": {"type": "text"}}}}
            },
            "aegis": {
                "properties": {"raw": {"type": "keyword", "index": False, "doc_values": False}}
            },
        },
    },
}
