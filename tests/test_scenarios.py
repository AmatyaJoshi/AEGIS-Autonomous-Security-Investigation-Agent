from __future__ import annotations

from lab.emulation.runner import Executor, load_hosts
from lab.emulation.scenario import (
    load_art_index,
    load_scenarios,
    validate_scenarios,
)

HOSTS = {"DC01": "windows", "WS01": "windows", "LNX01": "linux"}


def test_scenarios_valid_against_art_index() -> None:
    problems, coverage = validate_scenarios(load_scenarios(), load_art_index(), HOSTS)
    assert problems == [], f"scenario validation problems: {problems}"
    assert coverage["technique_count"] >= 40
    assert coverage["tactic_count"] >= 10


def test_every_guid_exists_and_matches_technique() -> None:
    index = load_art_index()
    for sc in load_scenarios():
        for step in sc.steps:
            assert step.test_guid in index, f"{sc.id}: {step.test_guid} not in ART index"
            assert index[step.test_guid].technique == step.technique


def test_dry_run_builds_commands_but_executes_nothing() -> None:
    hosts = load_hosts()
    index = load_art_index()
    execu = Executor("dry-run", vms_dir=None, hosts=hosts)  # type: ignore[arg-type]
    sc = next(s for s in load_scenarios() if s.platform == "windows")
    test = index[sc.steps[0].test_guid]
    ps = execu.atomic_command(test, {}, cleanup=True, timeout_s=60)
    assert "Invoke-AtomicTest" in ps
    assert test.technique in ps
    code, out, _err, printable = execu.run(hosts[sc.steps[0].host], ps, 60)
    assert code == 0 and out == "" and "Invoke-AtomicTest" in printable
