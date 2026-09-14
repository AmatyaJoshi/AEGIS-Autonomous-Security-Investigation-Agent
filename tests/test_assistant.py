"""AEGIS Copilot assistant: offline, grounded, guardrail-respecting (SPEC §9)."""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_API_DSN", f"sqlite:///{tmp_path / 'assist.db'}")
    import aegis.api.app as appmod

    importlib.reload(appmod)
    return TestClient(appmod.app)


def _token(c) -> str:
    r = c.post("/api/auth/login", json={"email": "analyst@aegis.local", "password": "aegis1234"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_assistant_requires_auth(tmp_path, monkeypatch) -> None:
    c = _client(tmp_path, monkeypatch)
    assert c.post("/api/assistant/ask", json={"question": "hi"}).status_code == 401
    assert c.get("/api/assistant/suggestions").status_code == 401


def test_assistant_grounded_answer_and_citations(tmp_path, monkeypatch) -> None:
    c = _client(tmp_path, monkeypatch)
    h = {"Authorization": f"Bearer {_token(c)}"}

    starters = c.get("/api/assistant/suggestions", headers=h).json()["starters"]
    assert len(starters) >= 4

    r = c.post("/api/assistant/ask", json={"question": "Explain MITRE technique T1003"}, headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["intent"] == "technique"
    assert "T1003" in body["answer"]
    assert any(cit["source"] == "MITRE ATT&CK KB" for cit in body["citations"])
    assert body["suggestions"]


def test_assistant_declines_execution_requests(tmp_path, monkeypatch) -> None:
    c = _client(tmp_path, monkeypatch)
    h = {"Authorization": f"Bearer {_token(c)}"}
    r = c.post(
        "/api/assistant/ask",
        json={"question": "isolate the host and block the C2 for me"},
        headers=h,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["guardrail_notice"], "must flag a guardrail notice for execution requests"
    assert "recommend-only" in body["guardrail_notice"].lower()
