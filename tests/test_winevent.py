from __future__ import annotations

from datetime import UTC

from lab.common.ecs import make_event_id, split_hashes, split_user, win_category
from lab.common.winevent import flatten_evtx, map_windows_event


def test_map_sysmon_process(sysmon_process_event) -> None:
    ev = map_windows_event(sysmon_process_event, dataset="otrf", dataset_ref="unit")
    assert ev is not None
    assert ev.event_code == "1"
    assert ev.event_category == "process"
    assert ev.event_action == "process_created"
    assert ev.host_name == "WS01"  # FQDN trimmed + upper
    assert ev.user_name == "adm.patel"
    assert ev.user_domain == "CORP"
    assert ev.process_name == "devtool64.exe"
    assert ev.process_parent_name == "powershell.exe"
    assert (
        ev.process_hash_sha256 == "11064e9edc605bd5b0c0a505538a0d5fd7de53883af342f091687cae8628acd0"
    )
    assert ev.process_integrity_level == "High"
    assert ev.timestamp.tzinfo is UTC


def test_map_security_logon(security_4624_event) -> None:
    ev = map_windows_event(security_4624_event, dataset="otrf", dataset_ref="unit")
    assert ev is not None
    assert ev.event_category == "authentication"
    assert ev.event_action == "logged_in"
    assert ev.event_outcome == "success"
    assert ev.user_target_name == "adm.patel"
    assert ev.logon_type == 3
    assert ev.source_ip == "10.10.20.31"


def test_event_id_is_deterministic(sysmon_process_event) -> None:
    a = map_windows_event(sysmon_process_event, dataset="otrf", dataset_ref="unit")
    b = map_windows_event(dict(sysmon_process_event), dataset="otrf", dataset_ref="unit")
    assert a and b and a.event_id == b.event_id
    assert len(a.event_id) == 32


def test_missing_timestamp_returns_none() -> None:
    assert (
        map_windows_event({"EventID": 1, "Channel": "x"}, dataset="otrf", dataset_ref="u") is None
    )


def test_flatten_evtx_nested() -> None:
    record = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                "EventID": 4688,
                "Channel": "Security",
                "Computer": "DC01.corp.local",
                "TimeCreated": {"#attributes": {"SystemTime": "2025-01-06T14:00:00Z"}},
            },
            "EventData": {
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "SubjectUserName": "adm.wu",
                "ProcessId": "0x abc",
            },
        }
    }
    flat = flatten_evtx(record)
    assert flat["EventID"] == 4688
    assert flat["Channel"] == "Security"
    ev = map_windows_event(flat, dataset="evtx_attack", dataset_ref="unit")
    assert ev is not None
    assert ev.process_name == "cmd.exe"
    assert ev.user_name == "adm.wu"


def test_helpers() -> None:
    assert split_user("CORP\\adm.patel") == ("adm.patel", "CORP")
    assert split_user("alice") == ("alice", None)
    h = split_hashes("SHA1=AB,MD5=cd,SHA256=EF")
    assert h == {"sha1": "ab", "md5": "cd", "sha256": "ef"}
    assert win_category("Security", "4625") == ("authentication", "logon_failed")
    assert win_category(None, None) == (None, None)
    assert len(make_event_id("otrf", "r", "{}")) == 32
