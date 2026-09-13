"""Flat ECS-style event record used for every lab telemetry source.

Elastic is the lab SIEM, so telemetry is normalised to Elastic Common Schema (ECS) field names and
indexed as-is; alerts raised *on top of* these events are then normalised to OCSF (Phase 2). Keeping
events in a single flat, typed record lets the same rows go to Elasticsearch (online) and to Parquet
-> DuckDB (``--offline``) without any per-backend mapping.

Every record carries:
* ``event_id`` - deterministic SHA-256 over (dataset, dataset_ref, raw) so re-loads are idempotent
  and EvidenceRefs resolve to the same id online and offline.
* ``dataset`` / ``dataset_ref`` - provenance (e.g. ``otrf`` / ``SDWIN-190301125905``).
* ``raw`` - the original event as JSON, verbatim. Nothing is lost during flattening.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any

import pyarrow as pa
from pydantic import BaseModel, ConfigDict, Field, field_validator

DATASETS = (
    "otrf",
    "evtx_attack",
    "bots",
    "cicids",
    "lab_emulation",
    "noise",
)


class EcsEvent(BaseModel):
    """One telemetry event, ECS field names flattened with underscores."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    event_id: str
    timestamp: datetime = Field(alias="@timestamp")
    dataset: str
    dataset_ref: str
    # event.*
    event_code: str | None = None  # EventID as string ("1", "4688", ...)
    event_provider: str | None = None  # "Microsoft-Windows-Sysmon"
    event_channel: str | None = None  # "Microsoft-Windows-Sysmon/Operational"
    event_category: str | None = None  # ECS category: process, authentication, network, file...
    event_action: str | None = None
    event_outcome: str | None = None
    # host.* / user.*
    host_name: str | None = None
    host_os_type: str | None = None  # windows | linux | network
    user_name: str | None = None
    user_domain: str | None = None
    user_target_name: str | None = None  # TargetUserName for logon events
    # process.*
    process_name: str | None = None
    process_pid: int | None = None
    process_entity_id: str | None = None  # ProcessGuid
    process_executable: str | None = None
    process_command_line: str | None = None
    process_parent_name: str | None = None
    process_parent_pid: int | None = None
    process_parent_executable: str | None = None
    process_parent_command_line: str | None = None
    process_hash_sha256: str | None = None
    process_hash_md5: str | None = None
    process_hash_imphash: str | None = None
    process_integrity_level: str | None = None
    # file.* / registry.* / dns.* / url.*
    file_path: str | None = None
    file_name: str | None = None
    file_hash_sha256: str | None = None
    registry_path: str | None = None
    registry_value: str | None = None
    registry_data: str | None = None
    dns_question_name: str | None = None
    url_original: str | None = None
    http_user_agent: str | None = None
    # source.* / destination.* / network.*
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    network_transport: str | None = None
    network_protocol: str | None = None
    network_bytes: int | None = None
    # winlog.* (for logon / service / task events)
    logon_type: int | None = None
    logon_id: str | None = None
    target_domain: str | None = None
    service_name: str | None = None
    task_name: str | None = None
    script_block_text: str | None = None
    message: str | None = None
    # provenance
    raw: str  # original event JSON, verbatim
    tags: list[str] = Field(default_factory=list)

    @field_validator("timestamp", mode="after")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)

    @field_validator("dataset")
    @classmethod
    def _known_dataset(cls, v: str) -> str:
        if v not in DATASETS:
            raise ValueError(f"unknown dataset {v!r}; expected one of {DATASETS}")
        return v

    def to_row(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True)

    def to_es_doc(self) -> dict[str, Any]:
        """Nest the flat record into proper ECS objects for Elasticsearch."""
        doc: dict[str, Any] = {"@timestamp": self.timestamp.isoformat(), "event": {}}
        for key, value in self.model_dump(exclude={"timestamp", "raw"}).items():
            if value is None or value == [] or key == "event_id":
                continue
            parts = ECS_PATHS.get(key, key).split(".")
            cur = doc
            for p in parts[:-1]:
                cur = cur.setdefault(p, {})
            cur[parts[-1]] = value
        doc["event"]["id"] = self.event_id
        doc["aegis"] = {"raw": self.raw}
        return doc


# flat attribute -> ECS dotted path
ECS_PATHS: dict[str, str] = {
    "dataset": "event.dataset",
    "dataset_ref": "event.dataset_ref",
    "event_code": "event.code",
    "event_provider": "event.provider",
    "event_channel": "winlog.channel",
    "event_category": "event.category",
    "event_action": "event.action",
    "event_outcome": "event.outcome",
    "host_name": "host.name",
    "host_os_type": "host.os.type",
    "user_name": "user.name",
    "user_domain": "user.domain",
    "user_target_name": "user.target.name",
    "process_name": "process.name",
    "process_pid": "process.pid",
    "process_entity_id": "process.entity_id",
    "process_executable": "process.executable",
    "process_command_line": "process.command_line",
    "process_parent_name": "process.parent.name",
    "process_parent_pid": "process.parent.pid",
    "process_parent_executable": "process.parent.executable",
    "process_parent_command_line": "process.parent.command_line",
    "process_hash_sha256": "process.hash.sha256",
    "process_hash_md5": "process.hash.md5",
    "process_hash_imphash": "process.pe.imphash",
    "process_integrity_level": "process.integrity_level",
    "file_path": "file.path",
    "file_name": "file.name",
    "file_hash_sha256": "file.hash.sha256",
    "registry_path": "registry.path",
    "registry_value": "registry.value",
    "registry_data": "registry.data.strings",
    "dns_question_name": "dns.question.name",
    "url_original": "url.original",
    "http_user_agent": "user_agent.original",
    "source_ip": "source.ip",
    "source_port": "source.port",
    "destination_ip": "destination.ip",
    "destination_port": "destination.port",
    "network_transport": "network.transport",
    "network_protocol": "network.protocol",
    "network_bytes": "network.bytes",
    "logon_type": "winlog.logon.type",
    "logon_id": "winlog.logon.id",
    "target_domain": "user.target.domain",
    "service_name": "service.name",
    "task_name": "winlog.event_data.TaskName",
    "script_block_text": "powershell.file.script_block_text",
    "message": "message",
    "tags": "tags",
}

_REQUIRED = {"event_id", "timestamp", "dataset", "dataset_ref", "raw"}


def _arrow_type(annotation: Any) -> pa.DataType:
    text = str(annotation)
    if "datetime" in text:
        return pa.timestamp("us", tz="UTC")
    if "list[str]" in text:
        return pa.list_(pa.string())
    if "int" in text:
        return pa.int64()
    return pa.string()


ARROW_SCHEMA: pa.Schema = pa.schema(
    [
        pa.field(field.alias or name, _arrow_type(field.annotation), nullable=name not in _REQUIRED)
        for name, field in EcsEvent.model_fields.items()
    ]
)


def make_event_id(dataset: str, dataset_ref: str, raw: str) -> str:
    h = hashlib.sha256()
    h.update(dataset.encode())
    h.update(b"\x00")
    h.update(dataset_ref.encode())
    h.update(b"\x00")
    h.update(raw.encode("utf-8", "surrogatepass"))
    return h.hexdigest()[:32]


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def to_int(v: Any) -> int | None:
    if v is None or v == "":
        return None
    try:
        s = str(v).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(float(s))
    except (TypeError, ValueError):
        return None


def parse_ts(*candidates: Any) -> datetime | None:
    """First parseable timestamp among candidates. Naive values are assumed UTC."""
    from dateutil import parser as dtp

    for c in candidates:
        if not c:
            continue
        try:
            dt = dtp.parse(str(c))
        except (ValueError, OverflowError):
            continue
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return None


def basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").rsplit("\\", 1)[-1] or None


def split_hashes(hashes: str | None) -> dict[str, str]:
    """Sysmon ``Hashes`` field ``SHA1=..,MD5=..,SHA256=..,IMPHASH=..`` -> dict (lower-case keys)."""
    out: dict[str, str] = {}
    if not hashes:
        return out
    for part in str(hashes).split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out


def split_user(user: str | None) -> tuple[str | None, str | None]:
    """``DOMAIN\\user`` -> (user, domain)."""
    if not user:
        return None, None
    if "\\" in user:
        dom, name = user.split("\\", 1)
        return name or None, dom or None
    return user, None


def batched(it: Iterable[EcsEvent], n: int) -> Iterator[list[EcsEvent]]:
    batch: list[EcsEvent] = []
    for e in it:
        batch.append(e)
        if len(batch) >= n:
            yield batch
            batch = []
    if batch:
        yield batch


# Windows EventID -> (ECS category, action). Used by every Windows-log loader.
WIN_EVENT_MAP: dict[tuple[str, str], tuple[str, str]] = {
    ("Microsoft-Windows-Sysmon/Operational", "1"): ("process", "process_created"),
    ("Microsoft-Windows-Sysmon/Operational", "3"): ("network", "network_connection"),
    ("Microsoft-Windows-Sysmon/Operational", "5"): ("process", "process_terminated"),
    ("Microsoft-Windows-Sysmon/Operational", "7"): ("library", "image_loaded"),
    ("Microsoft-Windows-Sysmon/Operational", "8"): ("process", "create_remote_thread"),
    ("Microsoft-Windows-Sysmon/Operational", "10"): ("process", "process_access"),
    ("Microsoft-Windows-Sysmon/Operational", "11"): ("file", "file_created"),
    ("Microsoft-Windows-Sysmon/Operational", "12"): ("registry", "registry_object_added"),
    ("Microsoft-Windows-Sysmon/Operational", "13"): ("registry", "registry_value_set"),
    ("Microsoft-Windows-Sysmon/Operational", "17"): ("file", "pipe_created"),
    ("Microsoft-Windows-Sysmon/Operational", "18"): ("file", "pipe_connected"),
    ("Microsoft-Windows-Sysmon/Operational", "22"): ("network", "dns_query"),
    ("Microsoft-Windows-Sysmon/Operational", "23"): ("file", "file_delete"),
    ("Security", "4624"): ("authentication", "logged_in"),
    ("Security", "4625"): ("authentication", "logon_failed"),
    ("Security", "4648"): ("authentication", "logon_explicit_credentials"),
    ("Security", "4672"): ("iam", "special_privileges_assigned"),
    ("Security", "4688"): ("process", "process_created"),
    ("Security", "4689"): ("process", "process_terminated"),
    ("Security", "4697"): ("configuration", "service_installed"),
    ("Security", "4698"): ("configuration", "scheduled_task_created"),
    ("Security", "4720"): ("iam", "user_created"),
    ("Security", "4728"): ("iam", "group_member_added"),
    ("Security", "4732"): ("iam", "group_member_added"),
    ("Security", "4768"): ("authentication", "kerberos_tgt_requested"),
    ("Security", "4769"): ("authentication", "kerberos_service_ticket_requested"),
    ("Security", "4776"): ("authentication", "ntlm_credential_validation"),
    ("Security", "5140"): ("network", "network_share_accessed"),
    ("Security", "5145"): ("network", "network_share_object_checked"),
    ("Security", "5156"): ("network", "connection_allowed"),
    ("System", "7045"): ("configuration", "service_installed"),
    ("Microsoft-Windows-PowerShell/Operational", "4104"): ("process", "script_block_logged"),
    ("Microsoft-Windows-PowerShell/Operational", "4103"): ("process", "module_logged"),
    ("Windows PowerShell", "400"): ("process", "engine_started"),
}


def win_category(channel: str | None, event_code: str | None) -> tuple[str | None, str | None]:
    if channel is None or event_code is None:
        return None, None
    return WIN_EVENT_MAP.get((channel, event_code), (None, None))
