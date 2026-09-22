"""Phase 1 case memory: Pulse client (retries, timeouts, budget), schema idempotency, blend math,
metadata-only boundary, network-off fallback within 2 s, and the triage_pre integration.
No network: every Pulse call goes through httpx.MockTransport. The one live test is marked
``network`` and skipped unless AEGIS_PULSE_API_KEY is set."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from aegis.graph.runner import InvestigationResult
from aegis.graph.state import Budget, ContextBundle, Hypothesis, Verdict
from aegis.llm.budget import BudgetGuard, OutboundDeniedError
from aegis.memory.priors import Prior, blend_p_tp, compute_priors, pick_prior, prior_weight
from aegis.memory.pulse_client import PulseClient, PulseUnavailableError
from aegis.memory.store import (
    TABLES,
    CaseRecord,
    FeedbackRecord,
    LocalStore,
    PulseStore,
    open_memory,
)
from aegis.schema.ocsf import (
    Analytic,
    Attack,
    DetectionFinding,
    FindingInfo,
    SeverityId,
    Technique,
    new_metadata,
)

HOST, USER, TITLE = "WS-FINANCE-07", "priya.natarajan", "Credential Store File Access on WS"
MSI_EXE = "C:\\Windows\\System32\\msiexec.exe"
MSI_CMD = "msiexec.exe /i C:\\Windows\\ccmcache\\agent.msi /qn /norestart"


def _result(inv_id: str = "inv-1", label: str = "true_positive") -> InvestigationResult:
    alert = DetectionFinding(
        time=datetime(2025, 1, 6, 14, tzinfo=UTC),
        metadata=new_metadata("Sigma", "SigmaHQ"),
        severity_id=SeverityId.HIGH,
        finding_info=FindingInfo(
            title=TITLE,
            uid="al-1",
            analytic=Analytic(name="r"),
            attacks=[Attack(technique=Technique(uid="T1003.001"))],
        ),
    )
    verdict = Verdict(
        label=label,  # type: ignore[arg-type]
        confidence=0.8,
        severity="high",
        techniques=["T1003.001"],
        triage_model_score=0.7,
        rationale=f"{HOST} {USER} did something",
    )
    return InvestigationResult(
        investigation_id=inv_id,
        alert=alert,
        verdict=verdict,
        context=ContextBundle(),
        hypotheses=[Hypothesis(id="H1", statement=f"{USER} on {HOST}", reasoning=HOST)],
        timeline=[],
        report_md=f"# Report\n{HOST} {USER} [E:abc]",
        report_json={},
        playbook_id=None,
        playbook=None,
        injection_flagged=False,
        spent=Budget(tool_calls=6, llm_calls=5, cost_usd=0.0),
        seconds=1.23,
        prompt_versions={"system": 1, "report": 1},
    )


def _case(inv_id: str, label: str = "true_positive") -> CaseRecord:
    return CaseRecord.from_result(_result(inv_id, label), reasoner="deterministic", model=None)


# ------------------------------------------------------------------ blend math
def test_prior_weight_and_blend() -> None:
    assert prior_weight(0) == 0.0
    assert prior_weight(20) == 0.5
    assert prior_weight(60) == 0.75
    p = Prior("T1003.001", 20, 0.9, 0.0, 0.0, "")
    blended, w = blend_p_tp(0.5, p)
    assert w == 0.5 and blended == pytest.approx(0.7)
    assert blend_p_tp(0.42, None) == (0.42, 0.0)
    assert blend_p_tp(1.5, None)[0] == 1.0  # clamped


def test_pick_prior_prefers_most_evidenced_technique_then_source() -> None:
    priors = {
        "T1": Prior("T1", 5, 0.1, 0, 0, ""),
        "T2": Prior("T2", 40, 0.8, 0, 0, ""),
        "source:Sigma": Prior("source:Sigma", 100, 0.5, 0, 0, ""),
    }
    assert pick_prior(priors, ["T1", "T2"], "Sigma").key == "T2"  # type: ignore[union-attr]
    assert pick_prior(priors, ["T9"], "Sigma").key == "source:Sigma"  # type: ignore[union-attr]
    assert pick_prior(priors, ["T9"], "Other") is None


def test_compute_priors_counts_and_override_rate() -> None:
    cases = [
        {"case_id": cid, "attack_technique_ids": ["T1"], "alert_source": "s", "verdict": v}
        for cid, v in (("a", "true_positive"), ("b", "false_positive"), ("c", "escalate"))
    ]
    fb = [{"case_id": "a", "agreed": True}, {"case_id": "b", "agreed": False}]
    pr = compute_priors(cases, fb)
    t1 = pr["T1"]
    assert t1.n == 3
    assert t1.tp_rate == pytest.approx(1 / 3, abs=1e-4)
    assert t1.escalate_rate == pytest.approx(1 / 3, abs=1e-4)
    assert t1.analyst_override_rate == 0.5  # 1 of 2 reviewed cases overridden
    assert pr["source:s"].n == 3


# ------------------------------------------------------------------ boundary
def test_case_record_is_metadata_only() -> None:
    rec = _case("inv-1")
    blob = json.dumps(rec.to_row()).lower()
    for secret in (HOST.lower(), USER.lower(), TITLE.lower(), "# report", "[e:"):
        assert secret not in blob, f"{secret!r} leaked into the Pulse record"
    assert rec.attack_technique_ids == ["T1003.001"]
    assert rec.verdict == "true_positive" and rec.triage_p_tp == 0.7 and rec.n_queries == 6
    assert len(rec.tenant_hash) == 16 and rec.tenant_hash != "lab"
    assert set(rec.to_row()) == {c["name"] for c in TABLES[0]["columns"]}


# ------------------------------------------------------------------ Pulse client
def _pulse_transport(
    log: list[dict[str, Any]], fail_first: int = 0, status: int = 503
) -> httpx.MockTransport:
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        body = json.loads(request.content)
        log.append({"headers": dict(request.headers), "body": body, "url": str(request.url)})
        if state["n"] <= fail_first:
            return httpx.Response(status, json={"error": "flaky"})
        a = body["action_type"]
        if a == "create_schema":
            return httpx.Response(200, json={"executed": True, "tables_created": 3, "errors": []})
        if a == "insert_data":
            return httpx.Response(200, json={"action": a, "status": "ok"})
        if a == "select_data":
            return httpx.Response(200, json={"action": a, "data": [], "status": "ok"})
        if a == "update_data":
            return httpx.Response(200, json={"action": a, "modified_count": 1})
        if a == "chat":
            return httpx.Response(200, json={"response": "T1059.001 ends as FP most often"})
        return httpx.Response(400, json={"error": "unknown"})

    return httpx.MockTransport(handler)


def _client(
    tmp_path: Path, transport: httpx.MockTransport, cap: int = 100, retries: int = 2
) -> PulseClient:
    return PulseClient(
        api_key="pk-test",
        base_url="https://pulse.evorozen.com",
        transport=transport,
        backoff_s=0.0,
        retries=retries,
        guard=BudgetGuard(external_calls_per_day=cap, state_path=tmp_path / "pb.json"),
    )


def test_client_request_shape_matches_docs(tmp_path: Path) -> None:
    log: list[dict[str, Any]] = []
    c = _client(tmp_path, _pulse_transport(log))
    c.create_schema(TABLES)
    c.insert("aegis_cases", {"case_id": "x"})
    c.select("aegis_priors", {"key": "T1"})
    c.update("aegis_priors", {"key": "T1"}, {"n": 2})
    assert c.chat("hello") == "T1059.001 ends as FP most often"
    assert all(e["url"] == "https://pulse.evorozen.com/api/neural" for e in log)
    assert all(e["headers"]["authorization"] == "Bearer pk-test" for e in log)
    assert log[0]["body"]["action_type"] == "create_schema"
    assert log[0]["body"]["data_payload"]["tables"][0]["name"] == "aegis_cases"
    assert log[1]["body"]["data_payload"] == {"table": "aegis_cases", "record": {"case_id": "x"}}
    assert log[2]["body"]["data_payload"] == {"table": "aegis_priors", "where": {"key": "T1"}}
    assert log[3]["body"]["data_payload"] == {
        "table": "aegis_priors",
        "where": {"key": "T1"},
        "changes": {"n": 2},
    }
    assert not hasattr(c, "delete")  # never exposed


def test_client_retries_then_succeeds_and_gives_up(tmp_path: Path) -> None:
    log: list[dict[str, Any]] = []
    c = _client(tmp_path, _pulse_transport(log, fail_first=2), retries=2)
    assert c.insert("aegis_cases", {"case_id": "x"})["status"] == "ok"
    assert len(log) == 3
    log.clear()
    c2 = _client(tmp_path, _pulse_transport(log, fail_first=5), retries=1)
    with pytest.raises(PulseUnavailableError, match="after 2 attempts"):
        c2.insert("aegis_cases", {"case_id": "y"})
    assert len(log) == 2


def test_client_rejected_key_does_not_retry(tmp_path: Path) -> None:
    log: list[dict[str, Any]] = []
    c = _client(tmp_path, _pulse_transport(log, fail_first=9, status=401), retries=3)
    with pytest.raises(PulseUnavailableError, match="rejected"):
        c.select("aegis_cases")
    assert len(log) == 1


def test_client_call_budget_trips_before_the_socket(tmp_path: Path) -> None:
    log: list[dict[str, Any]] = []
    c = _client(tmp_path, _pulse_transport(log), cap=2)
    c.insert("aegis_cases", {"case_id": "1"})
    c.insert("aegis_cases", {"case_id": "2"})
    with pytest.raises(PulseUnavailableError, match="budget"):
        c.insert("aegis_cases", {"case_id": "3"})
    assert len(log) == 2


def test_client_timeout_fallback_within_two_seconds(tmp_path: Path) -> None:
    def hang(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("simulated network off")

    c = _client(tmp_path, httpx.MockTransport(hang), retries=2)
    t0 = time.perf_counter()
    with pytest.raises(PulseUnavailableError, match="unreachable"):
        c.select("aegis_priors")
    assert time.perf_counter() - t0 < 2.0


def test_unlisted_base_url_fails_closed(tmp_path: Path) -> None:
    c = PulseClient(
        api_key="k",
        base_url="https://pulse.example.net",
        transport=_pulse_transport([]),
        guard=BudgetGuard(state_path=tmp_path / "pb.json"),
    )
    with pytest.raises(OutboundDeniedError):
        c.select("aegis_cases")


# ------------------------------------------------------------------ stores
def test_local_store_roundtrip_priors_and_analytics(tmp_path: Path) -> None:
    s = LocalStore(tmp_path / "m.db")
    s.record_case(_case("a"))
    s.record_case(_case("b", "false_positive"))
    s.record_feedback(FeedbackRecord("b", "true_positive", agreed=False, reason_code="override"))
    pr = s.priors()
    assert pr["T1003.001"].n == 2 and pr["T1003.001"].tp_rate == 0.5
    assert pr["T1003.001"].analyst_override_rate == 1.0
    a = s.analytics()
    assert a["source"] == "local" and "T1003.001: 1/2 FP" in a["answer"]
    assert s.status()["backend"] == "local"


def test_pulse_store_schema_is_idempotent_and_writes_are_batched(tmp_path: Path) -> None:
    log: list[dict[str, Any]] = []
    client = _client(tmp_path, _pulse_transport(log))
    store = PulseStore(client, LocalStore(tmp_path / "m.db"))
    assert store.ensure_schema() is True
    assert store.ensure_schema() is False  # remembered on disk, no second call
    store2 = PulseStore(_client(tmp_path, _pulse_transport(log)), LocalStore(tmp_path / "m.db"))
    assert store2.ensure_schema() is False
    assert sum(e["body"]["action_type"] == "create_schema" for e in log) == 1

    store.record_case(_case("a"))
    store.record_case(_case("b"))
    inserts = [e for e in log if e["body"]["action_type"] == "insert_data"]
    assert len(inserts) == 2 and inserts[0]["body"]["data_payload"]["table"] == "aegis_cases"
    assert store.pending_prior_keys == {"T1003.001", "source:offline"}
    n = store.flush_priors()  # select + insert per key, once per batch
    assert n == 2 and store.pending_prior_keys == set()
    assert store.status()["backend"] == "pulse" and store.status()["priors_source"] == "pulse"


def test_pulse_store_falls_back_to_local_when_network_is_off(tmp_path: Path) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network off")

    client = _client(tmp_path, httpx.MockTransport(down))
    local = LocalStore(tmp_path / "m.db")
    local.record_case(_case("a"))
    store = PulseStore(client, local)
    t0 = time.perf_counter()
    store.record_case(_case("b"))
    pr = store.priors()
    assert time.perf_counter() - t0 < 2.0
    assert pr["T1003.001"].n == 2, "local copy kept and used for priors"
    assert store.priors_source == "local" and store.status()["last_error"]
    assert store.analytics()["source"] == "local"


def test_open_memory_auto_without_key_is_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AEGIS_PULSE_API_KEY", raising=False)
    monkeypatch.setenv("AEGIS_MEMORY_BACKEND", "auto")
    mem = open_memory(local_path=tmp_path / "m.db")
    assert mem.backend == "local"
    monkeypatch.setenv("AEGIS_MEMORY_BACKEND", "pulse")
    assert open_memory(local_path=tmp_path / "m.db").backend == "local"


# ------------------------------------------------------------------ graph integration
def test_triage_pre_blends_prior_and_logs_both(tmp_path: Path) -> None:
    from aegis.graph.deps import Deps
    from aegis.graph.nodes.core import make_triage_pre
    from aegis.graph.reasoner import HeuristicReasoner

    class FakeTriage:
        name = "fake"

        def score(self, features: dict[str, Any]) -> dict[str, float]:
            return {"p_tp": 0.5, "p_fp": 0.5, "p_escalate": 0.0}

    local = LocalStore(tmp_path / "m.db")
    for i in range(20):  # 20 true positives for T1003.001 -> prior tp_rate 1.0, weight 0.5
        local.record_case(_case(f"c{i}"))

    class NoSiem:  # triage_pre never touches the SIEM
        pass

    deps = Deps(
        siem=NoSiem(),  # type: ignore[arg-type]
        reasoner=HeuristicReasoner(),
        triage=FakeTriage(),
        memory=local,
    )
    node = make_triage_pre(deps)
    res = _result("new")
    out = node({"alert": res.alert, "context": ContextBundle()})
    info = out["memory_prior"]
    assert info["key"] == "T1003.001" and info["n"] == 20 and info["weight"] == 0.5
    assert info["p_tp_model"] == 0.5 and info["p_tp_blended"] == 0.75
    assert info["source"] == "local"


def test_runner_records_case_via_memory(tmp_path: Path) -> None:
    """End-to-end: the runner writes one metadata-only record per investigation."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    from aegis.graph.deps import Deps
    from aegis.graph.reasoner import HeuristicReasoner
    from aegis.graph.runner import run_investigation
    from aegis.schema.normalize.sigma import finding_from_sigma
    from aegis.schema.normalize.sigma_match import SigmaRuleset
    from aegis.siem.duckdb import DuckDBSiem
    from lab.common.ecs import ARROW_SCHEMA
    from tests.test_graph import BENIGN_RULE, _mk_event

    events = [
        _mk_event(
            f"{i + 100:032x}",
            "SCCM01",
            "svc_sccm",
            MSI_EXE,
            MSI_CMD,
            parent="CcmExec.exe",
            ts=datetime(2025, 1, 6, 2, i, tzinfo=UTC),
        )
        for i in range(4)
    ]
    d = tmp_path / "snap" / "events" / "dataset=lab_emulation"
    d.mkdir(parents=True)
    pq.write_table(
        pa.Table.from_pylist([e.to_row() for e in events], schema=ARROW_SCHEMA), d / "p.parquet"
    )
    local = LocalStore(tmp_path / "m.db")
    rs = SigmaRuleset.from_yaml_docs([BENIGN_RULE])
    ev = {
        "event_id": f"{100:032x}",
        "@timestamp": datetime(2025, 1, 6, 2, 0, tzinfo=UTC),
        "event_action": "process_created",
        "event_channel": "Microsoft-Windows-Sysmon/Operational",
        "host_name": "SCCM01",
        "user_name": "svc_sccm",
        "process_name": "msiexec.exe",
        "process_executable": MSI_EXE,
        "process_command_line": MSI_CMD,
        "process_parent_name": "CcmExec.exe",
        "raw": "{}",
    }
    alert = finding_from_sigma(rs.match_event(ev)[0], ev)
    siem = DuckDBSiem(tmp_path / "snap")
    try:
        res = run_investigation(alert, Deps(siem=siem, reasoner=HeuristicReasoner(), memory=local))
    finally:
        siem.close()
    rows = local.cases()
    assert len(rows) == 1 and rows[0]["case_id"] == res.investigation_id
    assert "SCCM01" not in json.dumps(rows[0]) and "svc_sccm" not in json.dumps(rows[0])


# ------------------------------------------------------------------ live (opt-in)
@pytest.mark.network
@pytest.mark.skipif(not os.environ.get("AEGIS_PULSE_API_KEY"), reason="needs AEGIS_PULSE_API_KEY")
def test_live_pulse_write_three_cases_and_read_priors(tmp_path: Path) -> None:  # pragma: no cover
    store = open_memory("pulse", local_path=tmp_path / "m.db")
    assert isinstance(store, PulseStore)
    for i, label in enumerate(("true_positive", "false_positive", "true_positive")):
        store.record_case(_case(f"live-{i}", label))
    assert store.flush_priors() >= 1
    store._priors_cache = None
    pr = store.priors()
    assert store.priors_source == "pulse"
    assert "T1003.001" in pr and pr["T1003.001"].n >= 3
