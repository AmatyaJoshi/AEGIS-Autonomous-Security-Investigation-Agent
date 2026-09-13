from __future__ import annotations

from datetime import UTC, datetime

import pytest
from aegis.api.store import Store
from aegis.graph.runner import InvestigationResult
from aegis.graph.state import Budget, ContextBundle, Verdict
from aegis.schema.ocsf import (
    Analytic,
    Attack,
    DetectionFinding,
    FindingInfo,
    SeverityId,
    Technique,
    new_metadata,
)


def _result(inv_id: str = "inv-1") -> InvestigationResult:
    alert = DetectionFinding(
        time=datetime(2025, 1, 6, 14, tzinfo=UTC),
        metadata=new_metadata("Sigma", "SigmaHQ"),
        severity_id=SeverityId.HIGH,
        finding_info=FindingInfo(
            title="Credential Dumping",
            uid="al-1",
            analytic=Analytic(name="r"),
            attacks=[Attack(technique=Technique(uid="T1003.001"))],
        ),
    )
    verdict = Verdict(
        label="true_positive",
        confidence=0.8,
        severity="high",
        techniques=["T1003.001"],
        llm_score=0.85,
    )
    return InvestigationResult(
        investigation_id=inv_id,
        alert=alert,
        verdict=verdict,
        context=ContextBundle(),
        hypotheses=[],
        timeline=[],
        report_md="# Report\nCredential dumping observed [E:abc123].",
        report_json={"citations_ok": True},
        playbook_id="pb_credential_access",
        playbook=None,
        injection_flagged=False,
        spent=Budget(tool_calls=3, llm_calls=2),
        seconds=0.5,
    )


@pytest.fixture
def store(tmp_path) -> Store:
    return Store(dsn=f"sqlite:///{tmp_path / 'api.db'}")


def test_save_and_get(store: Store) -> None:
    store.save_result(_result(), gold_label="true_positive")
    summ = store.list_investigations()
    assert len(summ) == 1
    assert summ[0]["verdict"] == "true_positive"
    detail = store.get_investigation("inv-1")
    assert detail is not None
    assert detail["gold_label"] == "true_positive"
    assert "Credential dumping" in (detail["report_md"] or "")


def test_override_becomes_gold_label(store: Store) -> None:
    store.save_result(_result(), gold_label="true_positive")
    store.add_review("inv-1", analyst="alice", action="override", override_verdict="false_positive")
    detail = store.get_investigation("inv-1")
    assert detail is not None
    assert detail["gold_label"] == "false_positive"  # override replaced the label
    assert detail["reviews"][0]["action"] == "override"


def test_metrics(store: Store) -> None:
    store.save_result(_result("inv-1"), gold_label="true_positive")
    m = store.metrics()
    assert m["total"] == 1
    assert m["by_verdict"]["true_positive"] == 1
    assert m["accuracy_vs_gold"] == 1.0


def test_api_endpoints(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_API_DSN", f"sqlite:///{tmp_path / 'api2.db'}")
    import importlib

    import aegis.api.app as appmod

    importlib.reload(appmod)
    from fastapi.testclient import TestClient

    appmod.get_store().save_result(_result("inv-9"), gold_label="true_positive")
    c = TestClient(appmod.app)
    assert c.get("/health").json()["status"] == "ok"
    q = c.get("/api/queue").json()
    assert any(i["investigation_id"] == "inv-9" for i in q)
    d = c.get("/api/investigations/inv-9").json()
    assert d["verdict"] == "true_positive"
    assert c.get("/api/investigations/missing").status_code == 404
