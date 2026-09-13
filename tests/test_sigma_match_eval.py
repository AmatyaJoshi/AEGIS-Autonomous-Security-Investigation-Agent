from __future__ import annotations

from aegis.schema.normalize.sigma_match import SigmaRuleset

RULE = {
    "title": "Rundll32 comsvcs LSASS Dump",
    "id": "r-comsvcs",
    "status": "test",
    "level": "high",
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {
        "selection": {
            "Image|endswith": "\\rundll32.exe",
            "CommandLine|contains|all": ["comsvcs", "MiniDump"],
        },
        "condition": "selection",
    },
    "tags": ["attack.credential-access", "attack.t1003.001"],
}

MULTI = {
    "title": "Two of three",
    "id": "r-multi",
    "status": "test",
    "level": "medium",
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {
        "sel_a": {"Image|endswith": "\\powershell.exe"},
        "sel_b": {"CommandLine|contains": "downloadstring"},
        "sel_c": {"CommandLine|contains": "hidden"},
        "condition": "sel_a and (sel_b or sel_c)",
    },
    "tags": ["attack.execution", "attack.t1059.001"],
}


def _event(**kw: object) -> dict:
    base = {
        "event_id": "e1",
        "event_action": "process_created",
        "event_channel": "Microsoft-Windows-Sysmon/Operational",
    }
    base.update(kw)
    return base


def test_matches_credential_dump() -> None:
    rs = SigmaRuleset.from_yaml_docs([RULE])
    ev = _event(
        process_executable="C:\\Windows\\System32\\rundll32.exe",
        process_command_line="rundll32 C:\\windows\\System32\\comsvcs.dll MiniDump 700 x.dmp",
    )
    m = rs.match_event(ev)
    assert m and m[0].techniques == ("T1003.001",)


def test_no_match_wrong_category() -> None:
    rs = SigmaRuleset.from_yaml_docs([RULE])
    ev = _event(
        event_action="network_connection",
        process_executable="C:\\Windows\\System32\\rundll32.exe",
        process_command_line="comsvcs MiniDump",
    )
    assert rs.match_event(ev) == []


def test_all_modifier_requires_both_terms() -> None:
    rs = SigmaRuleset.from_yaml_docs([RULE])
    ev = _event(process_executable="C:\\rundll32.exe", process_command_line="comsvcs only")
    assert rs.match_event(ev) == []  # missing MiniDump


def test_condition_and_or() -> None:
    rs = SigmaRuleset.from_yaml_docs([MULTI])
    hit = _event(
        process_executable="C:\\powershell.exe",
        process_command_line="powershell -w hidden something",
    )
    assert rs.match_event(hit)
    miss = _event(process_executable="C:\\powershell.exe", process_command_line="benign")
    assert rs.match_event(miss) == []
