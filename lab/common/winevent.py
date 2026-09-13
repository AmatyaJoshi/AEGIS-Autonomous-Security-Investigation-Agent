"""Windows event (Sysmon / Security / PowerShell / System) -> ``EcsEvent`` mapping.

Two input shapes are handled:
* **flat** dicts as published by OTRF Security-Datasets (``{"Hostname":..., "EventID": 1,
  "Channel":..., "Image":..., "CommandLine":...}``);
* **nested** ``{"Event": {"System": {...}, "EventData": {...}}}`` as produced by the ``evtx``
  parser (EVTX-ATTACK-SAMPLES) - flattened first, then mapped by the same code path.

Mapping is intentionally conservative: only fields with an unambiguous ECS home are promoted; the
full original stays in ``raw``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from lab.common.ecs import (
    EcsEvent,
    basename,
    canonical_json,
    make_event_id,
    parse_ts,
    split_hashes,
    split_user,
    to_int,
    win_category,
)


def flatten_evtx(record: dict[str, Any]) -> dict[str, Any]:
    """Flatten an ``evtx`` JSON record into the OTRF-style flat dict."""
    ev = record.get("Event", record)
    system = ev.get("System") or {}
    flat: dict[str, Any] = {}

    def attr(node: Any, key: str) -> Any:
        if isinstance(node, dict):
            attrs = node.get("#attributes") or {}
            return attrs.get(key, node.get(key))
        return None

    prov = system.get("Provider")
    flat["SourceName"] = attr(prov, "Name")
    flat["ProviderGuid"] = attr(prov, "Guid")
    eid = system.get("EventID")
    flat["EventID"] = eid.get("#text") if isinstance(eid, dict) else eid
    flat["Channel"] = system.get("Channel")
    flat["Hostname"] = system.get("Computer")
    flat["EventRecordID"] = system.get("EventRecordID")
    flat["Task"] = system.get("Task")
    flat["Level"] = system.get("Level")
    flat["Keywords"] = system.get("Keywords")
    flat["TimeCreated"] = attr(system.get("TimeCreated"), "SystemTime")
    exe = system.get("Execution")
    flat["ExecutionProcessID"] = attr(exe, "ProcessID")
    sec = system.get("Security")
    if sec:
        flat["SecurityUserID"] = attr(sec, "UserID")

    for section in ("EventData", "UserData"):
        data = ev.get(section)
        if isinstance(data, dict):
            for k, v in data.items():
                if k == "#attributes":
                    continue
                if isinstance(v, dict):
                    # e.g. {"Data": [...]} for unnamed params, or nested UserData objects
                    if "#text" in v:
                        flat[k] = v["#text"]
                    else:
                        for kk, vv in v.items():
                            flat[kk if kk != "#text" else k] = vv
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        flat[f"{k}{i}"] = item
                else:
                    flat[k] = v
    return flat


def map_windows_event(
    flat: dict[str, Any],
    *,
    dataset: str,
    dataset_ref: str,
    tags: list[str] | None = None,
    default_ts: datetime | None = None,
) -> EcsEvent | None:
    raw = canonical_json(flat)
    ts = (
        parse_ts(
            flat.get("@timestamp"),
            flat.get("UtcTime"),
            flat.get("TimeCreated"),
            flat.get("EventTime"),
        )
        or default_ts
    )
    if ts is None:
        return None

    channel = flat.get("Channel")
    code = str(flat.get("EventID")) if flat.get("EventID") is not None else None
    category, action = win_category(channel, code)

    # --- user -------------------------------------------------------------------------------
    user, domain = split_user(flat.get("User"))
    if user is None:
        user = flat.get("SubjectUserName") or flat.get("AccountName") or flat.get("UserName")
        domain = flat.get("SubjectDomainName") or domain
    if user in ("-", ""):
        user = None
    target_user = flat.get("TargetUserName")
    if target_user in ("-", ""):
        target_user = None

    # --- process ------------------------------------------------------------------------------
    image = flat.get("Image") or flat.get("NewProcessName") or flat.get("ProcessName")
    if isinstance(image, str) and image in ("-", ""):
        image = None
    parent_image = flat.get("ParentImage") or flat.get("ParentProcessName")
    if isinstance(parent_image, str) and parent_image in ("-", ""):
        parent_image = None
    hashes = split_hashes(flat.get("Hashes"))
    # Sysmon EID 10 (ProcessAccess) uses SourceImage/TargetImage
    if code == "10" and image is None:
        image = flat.get("SourceImage")
    # Sysmon EID 7 (ImageLoad): Image is the process, ImageLoaded the DLL
    file_path = flat.get("TargetFilename") or flat.get("ImageLoaded") or flat.get("TargetObject")
    if code == "7":
        file_path = flat.get("ImageLoaded")
    registry_path = flat.get("TargetObject") if code in ("12", "13", "14") else None

    pid = to_int(flat.get("ProcessId") or flat.get("NewProcessId") or flat.get("SourceProcessId"))
    # Security 4688: "ProcessId" is the *creator* (parent) pid, "NewProcessId" the child.
    ppid = to_int(
        flat.get("ParentProcessId") or (flat.get("ProcessId") if code == "4688" else None)
    )

    hostname = flat.get("Hostname") or flat.get("Computer")
    if isinstance(hostname, str):
        hostname = hostname.upper().split(".")[0]

    ev = EcsEvent(
        event_id=make_event_id(dataset, dataset_ref, raw),
        timestamp=ts,
        dataset=dataset,
        dataset_ref=dataset_ref,
        event_code=code,
        event_provider=flat.get("SourceName") or flat.get("ProviderName"),
        event_channel=channel,
        event_category=category,
        event_action=action,
        event_outcome=_outcome(flat, code),
        host_name=hostname,
        host_os_type="windows",
        user_name=user,
        user_domain=domain if domain not in ("-", "") else None,
        user_target_name=target_user,
        process_name=basename(image),
        process_pid=pid,
        process_entity_id=flat.get("ProcessGuid") or flat.get("SourceProcessGUID"),
        process_executable=image,
        process_command_line=flat.get("CommandLine") or flat.get("ProcessCommandLine"),
        process_parent_name=basename(parent_image),
        process_parent_pid=ppid,
        process_parent_executable=parent_image,
        process_parent_command_line=flat.get("ParentCommandLine"),
        process_hash_sha256=hashes.get("sha256"),
        process_hash_md5=hashes.get("md5"),
        process_hash_imphash=hashes.get("imphash"),
        process_integrity_level=flat.get("IntegrityLevel"),
        file_path=file_path if isinstance(file_path, str) else None,
        file_name=basename(file_path) if isinstance(file_path, str) else None,
        registry_path=registry_path,
        registry_data=str(flat["Details"]) if code == "13" and "Details" in flat else None,
        dns_question_name=flat.get("QueryName") if code == "22" else None,
        source_ip=_ip(flat.get("SourceIp") or flat.get("IpAddress") or flat.get("SourceAddress")),
        source_port=to_int(flat.get("SourcePort") or flat.get("IpPort")),
        destination_ip=_ip(flat.get("DestinationIp") or flat.get("DestAddress")),
        destination_port=to_int(flat.get("DestinationPort") or flat.get("DestPort")),
        network_transport=(str(flat["Protocol"]) if flat.get("Protocol") else None)
        if code in ("3", "5156")
        else None,
        logon_type=to_int(flat.get("LogonType")),
        logon_id=flat.get("LogonId") or flat.get("SubjectLogonId") or flat.get("TargetLogonId"),
        target_domain=flat.get("TargetDomainName"),
        service_name=flat.get("ServiceName"),
        task_name=flat.get("TaskName"),
        script_block_text=flat.get("ScriptBlockText"),
        message=str(flat.get("Message"))[:4000] if flat.get("Message") else None,
        raw=raw,
        tags=list(tags or []),
    )
    return ev


def _outcome(flat: dict[str, Any], code: str | None) -> str | None:
    if code == "4625":
        return "failure"
    if code in ("4624", "4648", "4768", "4769", "4776"):
        status = str(flat.get("Status", "0x0"))
        return "success" if status in ("0x0", "0", "-") else "failure"
    return None


def _ip(v: Any) -> str | None:
    if not v or v in ("-", "::1", "0.0.0.0"):
        return None
    s = str(v)
    return s[7:] if s.startswith("::ffff:") else s
