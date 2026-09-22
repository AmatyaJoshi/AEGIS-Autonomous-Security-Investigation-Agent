"""Zero-cost LLM path (COST.md): providers over httpx with recorded responses, budget guards that
trip into degraded mode (never an exception out of the reasoner, never a paid retry), and the
outbound allow-list that fails closed. No live LLM or network call is made here."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from aegis.llm.budget import BudgetGuard, DegradedError, OutboundDeniedError, check_outbound
from aegis.llm.router import LLMRouter
from pydantic import BaseModel


class Out(BaseModel):
    label: str
    confidence: float


def _ollama_transport(calls: list[dict], reply: dict | None = None) -> httpx.MockTransport:
    reply = reply or {"label": "false_positive", "confidence": 0.8}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "llama3.1:8b"}]})
        body = json.loads(request.content)
        calls.append(body)
        return httpx.Response(
            200,
            json={
                "model": body["model"],
                "message": {"role": "assistant", "content": json.dumps(reply)},
                "prompt_eval_count": 120,
                "eval_count": 30,
            },
        )

    return httpx.MockTransport(handler)


def _router(tmp_path: Path, transport: httpx.MockTransport, **guard_kw: int) -> LLMRouter:
    guard = BudgetGuard(state_path=tmp_path / "budget.json", **guard_kw)
    return LLMRouter(
        provider="ollama",
        ollama_url="http://localhost:11434",
        cache_dir=tmp_path / "cache",
        guard=guard,
        transport=transport,
    )


def test_ollama_provider_request_shape_and_schema_parse(tmp_path: Path) -> None:
    calls: list[dict] = []
    r = _router(tmp_path, _ollama_transport(calls))
    assert r.available and r.resolve_provider() == "ollama"
    out = r.complete_schema("sys", "user", Out)
    assert out == Out(label="false_positive", confidence=0.8)
    body = calls[0]
    assert body["model"] == "llama3.1:8b" and body["format"] == "json" and body["stream"] is False
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert body["options"]["temperature"] == 0.0
    d = r.describe()
    assert d["cost_mode"] == "normal" and d["total_cost_usd"] == 0.0 and d["total_tokens"] == 150


def test_cache_makes_reruns_free(tmp_path: Path) -> None:
    calls: list[dict] = []
    r = _router(tmp_path, _ollama_transport(calls))
    r.complete("s", "u")
    second = r.complete("s", "u")
    assert len(calls) == 1 and second.cached is True


def test_per_run_call_cap_trips_to_degraded_not_exception(tmp_path: Path) -> None:
    calls: list[dict] = []
    r = _router(tmp_path, _ollama_transport(calls), calls_per_run=2)
    r.complete("s", "u1")
    r.complete("s", "u2")
    with pytest.raises(DegradedError):
        r.complete("s", "u3")
    assert len(calls) == 2, "no call is made once the cap is reached"
    assert r.cost_mode == "degraded" and "per-run" in (r.guard.degraded_reason or "")


def test_per_day_token_cap_persists_across_routers(tmp_path: Path) -> None:
    calls: list[dict] = []
    r1 = _router(tmp_path, _ollama_transport(calls), tokens_per_day=200)
    r1.complete("s", "u1")  # 150 tokens
    r1.complete("s", "u2")  # 300 > 200 -> recorded, next call must trip
    r2 = _router(tmp_path, _ollama_transport(calls), tokens_per_day=200)
    with pytest.raises(DegradedError):
        r2.complete("s", "u3")
    assert len(calls) == 2


def test_provider_outage_degrades_and_reasoner_falls_back(tmp_path: Path) -> None:
    """Ollama answers /api/tags (so it is 'available') then dies: the LLMReasoner must return a
    deterministic hypothesis set instead of raising."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": []})
        raise httpx.ConnectError("boom")

    r = _router(tmp_path, httpx.MockTransport(handler))
    from datetime import UTC, datetime

    from aegis.graph.llm_reasoner import LLMReasoner
    from aegis.graph.state import ContextBundle
    from aegis.schema.normalize.sigma import finding_from_sigma
    from aegis.tools.sigma_match import SigmaRuleset

    rule = {
        "title": "Credential Store File Access",
        "id": "r-mk",
        "status": "test",
        "level": "critical",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"sel": {"CommandLine|contains": "ntds.dit"}, "condition": "sel"},
        "tags": ["attack.credential-access", "attack.t1003.001"],
    }
    ev = {
        "event_id": f"{0:032x}",
        "@timestamp": datetime(2025, 1, 6, 14, 0, tzinfo=UTC),
        "event_action": "process_created",
        "event_channel": "Microsoft-Windows-Sysmon/Operational",
        "host_name": "WS01",
        "user_name": "intruder",
        "process_name": "credtool.exe",
        "process_command_line": "credtool.exe --export ntds.dit",
        "raw": "{}",
    }
    rs = SigmaRuleset.from_yaml_docs([rule])
    alert = finding_from_sigma(rs.match_event(ev)[0], ev)
    reasoner = LLMReasoner(r)
    out = reasoner.hypothesize(alert, ContextBundle())
    assert out.hypotheses, "fallback produced hypotheses"
    assert reasoner.fallbacks == 1
    assert r.cost_mode == "degraded" and "unavailable" in (r.guard.degraded_reason or "")


def test_paid_providers_disabled_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("AEGIS_ALLOW_PAID_PROVIDERS", raising=False)

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no ollama")

    r = LLMRouter(
        provider="anthropic",
        cache_dir=tmp_path,
        guard=BudgetGuard(state_path=tmp_path / "b.json"),
        transport=httpx.MockTransport(down),
    )
    assert r.available is False


def test_groq_and_gemini_request_shapes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[request.url.host] = request
        if "groq" in request.url.host:
            return httpx.Response(
                200,
                json={
                    "model": "llama-3.1-8b-instant",
                    "choices": [{"message": {"content": '{"label":"escalate","confidence":0.5}'}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                },
            )
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {"content": {"parts": [{"text": '{"label":"true_positive","confidence":0.9}'}]}}
                ],
                "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 3},
            },
        )

    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    monkeypatch.setenv("GEMINI_API_KEY", "gm-test")
    g = LLMRouter(
        provider="groq",
        cache_dir=tmp_path / "g",
        guard=BudgetGuard(state_path=tmp_path / "b1.json"),
        transport=httpx.MockTransport(handler),
    )
    assert g.complete_schema("s", "u", Out).label == "escalate"
    req = seen["api.groq.com"]
    assert req.headers["authorization"] == "Bearer gsk-test"
    assert json.loads(req.content)["response_format"] == {"type": "json_object"}
    assert g.total_cost_usd == 0.0

    m = LLMRouter(
        provider="gemini",
        cache_dir=tmp_path / "m",
        guard=BudgetGuard(state_path=tmp_path / "b2.json"),
        transport=httpx.MockTransport(handler),
    )
    assert m.complete_schema("s", "u", Out).label == "true_positive"
    req = seen["generativelanguage.googleapis.com"]
    assert req.headers["x-goog-api-key"] == "gm-test"
    body = json.loads(req.content)
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert m.total_cost_usd == 0.0


def test_outbound_allowlist_fails_closed() -> None:
    assert check_outbound("http://localhost:11434/api/chat") == "localhost"
    assert check_outbound("https://api.groq.com/openai/v1/chat/completions") == "api.groq.com"
    assert check_outbound("https://pulse.evorozen.com/api/neural") == "pulse.evorozen.com"
    with pytest.raises(OutboundDeniedError):
        check_outbound("https://api.openai.example.net/v1")
    with pytest.raises(OutboundDeniedError):
        check_outbound("https://evil.example.com/")


def test_router_with_unlisted_ollama_host_is_not_available(tmp_path: Path) -> None:
    r = LLMRouter(
        provider="ollama",
        ollama_url="http://ollama.somewhere.example.net:11434",
        cache_dir=tmp_path,
        guard=BudgetGuard(state_path=tmp_path / "b.json"),
        transport=_ollama_transport([]),
    )
    assert r.available is False
