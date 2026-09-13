"""Shared ECS-event -> OCSF object extraction (observables, evidences, device, actor).

Used by every source normaliser so an alert's observables and evidence are consistent regardless of
whether the alert came from a Sigma match, an Elastic detection or a Splunk notable.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from aegis.schema.ocsf import (
    Actor,
    Device,
    Evidences,
    File,
    Fingerprint,
    NetworkEndpoint,
    Observable,
    ObservableTypeId,
    Process,
    User,
)

_HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")


def _add(
    observables: list[Observable],
    seen: set[tuple[int, str]],
    name: str,
    type_id: ObservableTypeId,
    value: Any,
) -> None:
    if value is None:
        return
    v = str(value).strip()
    if not v or v in ("-", "N/A"):
        return
    key = (int(type_id), v.lower())
    if key in seen:
        return
    seen.add(key)
    observables.append(Observable(name=name, type_id=type_id, value=v))


def observables_from_event(ev: dict[str, Any]) -> list[Observable]:
    """Extract the entities an analyst would pivot on from a flat ECS event row."""
    out: list[Observable] = []
    seen: set[tuple[int, str]] = set()
    _add(out, seen, "device.hostname", ObservableTypeId.HOSTNAME, ev.get("host_name"))
    _add(out, seen, "actor.user.name", ObservableTypeId.USER_NAME, ev.get("user_name"))
    _add(out, seen, "user.target.name", ObservableTypeId.USER_NAME, ev.get("user_target_name"))
    _add(out, seen, "actor.process.name", ObservableTypeId.PROCESS_NAME, ev.get("process_name"))
    _add(
        out,
        seen,
        "actor.process.cmd_line",
        ObservableTypeId.COMMAND_LINE,
        ev.get("process_command_line"),
    )
    _add(
        out,
        seen,
        "actor.process.parent.name",
        ObservableTypeId.PROCESS_NAME,
        ev.get("process_parent_name"),
    )
    _add(
        out,
        seen,
        "actor.process.file.hashes.sha256",
        ObservableTypeId.HASH,
        ev.get("process_hash_sha256"),
    )
    _add(out, seen, "src_endpoint.ip", ObservableTypeId.IP_ADDRESS, ev.get("source_ip"))
    _add(out, seen, "dst_endpoint.ip", ObservableTypeId.IP_ADDRESS, ev.get("destination_ip"))
    _add(out, seen, "file.path", ObservableTypeId.FILE_NAME, ev.get("file_path"))
    _add(out, seen, "dns.hostname", ObservableTypeId.HOSTNAME, ev.get("dns_question_name"))
    _add(out, seen, "http.user_agent", ObservableTypeId.HTTP_USER_AGENT, ev.get("http_user_agent"))
    _add(out, seen, "registry_key.path", ObservableTypeId.REGISTRY_KEY, ev.get("registry_path"))
    return out


def process_from_event(ev: dict[str, Any]) -> Process | None:
    if not any(ev.get(k) for k in ("process_name", "process_executable", "process_command_line")):
        return None
    hashes: list[Fingerprint] = []
    for algo, key in (
        ("SHA-256", "process_hash_sha256"),
        ("MD5", "process_hash_md5"),
        ("IMPHASH", "process_hash_imphash"),
    ):
        if ev.get(key):
            hashes.append(Fingerprint(algorithm=algo, value=str(ev[key])))
    parent = None
    if ev.get("process_parent_name") or ev.get("process_parent_executable"):
        parent = Process(
            name=ev.get("process_parent_name"),
            cmd_line=ev.get("process_parent_command_line"),
            pid=_int(ev.get("process_parent_pid")),
            file=File(name=ev.get("process_parent_name"), path=ev.get("process_parent_executable")),
        )
    return Process(
        name=ev.get("process_name"),
        cmd_line=ev.get("process_command_line"),
        pid=_int(ev.get("process_pid")),
        uid=ev.get("process_entity_id"),
        integrity=ev.get("process_integrity_level"),
        file=File(name=ev.get("process_name"), path=ev.get("process_executable"), hashes=hashes),
        parent_process=parent,
    )


def device_from_event(ev: dict[str, Any]) -> Device | None:
    if not ev.get("host_name"):
        return None
    return Device(
        hostname=ev.get("host_name"), name=ev.get("host_name"), type=ev.get("host_os_type")
    )


def actor_from_event(ev: dict[str, Any]) -> Actor | None:
    user = None
    if ev.get("user_name"):
        user = User(name=ev.get("user_name"), domain=ev.get("user_domain"))
    proc = process_from_event(ev)
    if user is None and proc is None:
        return None
    return Actor(user=user, process=proc)


def evidence_from_event(ev: dict[str, Any], raw: str | None = None) -> Evidences:
    src = None
    dst = None
    if ev.get("source_ip"):
        src = NetworkEndpoint(ip=ev.get("source_ip"), port=_int(ev.get("source_port")))
    if ev.get("destination_ip"):
        dst = NetworkEndpoint(ip=ev.get("destination_ip"), port=_int(ev.get("destination_port")))
    return Evidences(
        actor=actor_from_event(ev),
        process=process_from_event(ev),
        device=device_from_event(ev),
        src_endpoint=src,
        dst_endpoint=dst,
        event_uids=[ev["event_id"]] if ev.get("event_id") else [],
        data={"raw": raw}
        if raw
        else {"ecs": {k: v for k, v in ev.items() if v is not None and k != "raw"}},
    )


def parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    from dateutil import parser as dtp

    dt = dtp.parse(str(value))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _int(v: Any) -> int | None:
    try:
        return int(v) if v is not None and str(v) != "" else None
    except (TypeError, ValueError):
        return None


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
