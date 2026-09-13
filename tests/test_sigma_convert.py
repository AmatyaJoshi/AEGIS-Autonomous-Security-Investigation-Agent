from __future__ import annotations

import pytest
from lab.rules.convert import SigmaRuleRecord, convert_rules

RULE = """
title: Rundll32 comsvcs LSASS Dump
id: 00000000-0000-0000-0000-000000000001
status: test
description: Detects comsvcs.dll MiniDump of LSASS via rundll32
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
    CommandLine|contains|all: ['comsvcs', 'MiniDump']
  condition: selection
level: high
tags: [attack.credential-access, attack.t1003.001]
"""


@pytest.fixture(scope="module")
def converted() -> SigmaRuleRecord:
    rec = SigmaRuleRecord(
        id="r1",
        title="t",
        logsource={"product": "windows", "category": "process_creation"},
        path="p.yml",
        yaml=RULE,
        techniques=["T1003.001"],
    )
    return convert_rules([rec])[0]


def test_esql_and_spl_generated(converted: SigmaRuleRecord) -> None:
    assert converted.esql, converted.esql_error
    assert converted.spl, converted.spl_error
    assert "comsvcs" in converted.esql.lower()
    assert "comsvcs" in converted.spl.lower()


def test_esql_targets_ecs_fields(converted: SigmaRuleRecord) -> None:
    # ecs_windows pipeline maps Image -> process.executable
    assert "process." in converted.esql


def test_spl_targets_sysmon(converted: SigmaRuleRecord) -> None:
    assert "EventID=1" in converted.spl or "Image=" in converted.spl
