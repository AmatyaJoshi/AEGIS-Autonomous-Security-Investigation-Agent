"""LLM router (SPEC §2.1 LiteLLM tier): provider selection, JSON-schema parsing, caching, cost.

Zero-cost by construction (COST.md):

* **Providers** are plain ``httpx`` calls, no vendor SDKs. Order in ``auto`` mode: local **Ollama**
  (``AEGIS_OLLAMA_URL``), then the free tiers of **Groq** (``GROQ_API_KEY``) and **Gemini**
  (``GEMINI_API_KEY``). Paid Anthropic/OpenAI endpoints are only reachable when
  ``AEGIS_ALLOW_PAID_PROVIDERS=1`` is set explicitly *and* a key is present; nothing in the repo
  sets it.
* Every call goes through :class:`aegis.llm.budget.BudgetGuard` (per-run call cap, per-day token
  cap) and the outbound allow-list. Reaching a cap or losing the provider raises
  :class:`DegradedError`; ``LLMReasoner`` catches it and uses the deterministic reasoner, and the
  API reports ``cost_mode: degraded``.
* Responses are cached by content hash (SPEC §8.5) so benchmark reruns are deterministic and free.
* Every output is validated against a Pydantic schema from :mod:`aegis.llm.schemas`, one retry.

If no provider is configured the router reports ``available == False`` and the graph never
touches this module.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from aegis.llm.budget import (
    BudgetGuard,
    DegradedError,
    OutboundDeniedError,
    check_outbound,
    get_guard,
)

log = logging.getLogger("aegis.llm")
T = TypeVar("T", bound=BaseModel)

PROVIDERS = ("ollama", "groq", "gemini", "anthropic", "openai")
FREE_PROVIDERS = ("ollama", "groq", "gemini")

DEFAULT_MODELS: dict[str, str] = {
    "ollama": "llama3.1:8b",
    "groq": "llama-3.1-8b-instant",
    "gemini": "gemini-2.0-flash",
    "anthropic": "claude-fable-5-1",
    "openai": "gpt-4o-mini",
}

# Rough public prices (USD per 1M tokens) for cost accounting on the *paid* providers only.
_PRICES: dict[str, tuple[float, float]] = {
    "claude-fable-5-1": (3.0, 15.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "gpt-4o": (2.5, 10.0),
    "gpt-4o-mini": (0.15, 0.6),
}


class ProviderError(RuntimeError):
    """Transport or HTTP failure talking to a provider (turned into DegradedError by the router)."""


@dataclass
class LLMResponse:
    text: str
    model: str
    provider: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    cached: bool = False
    seconds: float = 0.0


@dataclass
class LLMRouter:
    provider: str = field(default_factory=lambda: os.environ.get("AEGIS_LLM_PROVIDER", "auto"))
    model: str | None = field(default_factory=lambda: os.environ.get("AEGIS_LLM_MODEL"))
    temperature: float = 0.0
    cache_dir: Path | None = None
    max_tokens: int = 2048
    timeout_s: float = field(
        default_factory=lambda: float(os.environ.get("AEGIS_LLM_TIMEOUT_S", "180"))
    )
    ollama_url: str = field(
        default_factory=lambda: os.environ.get("AEGIS_OLLAMA_URL", "http://localhost:11434")
    )
    guard: BudgetGuard = field(default_factory=get_guard)
    transport: httpx.BaseTransport | None = None  # tests inject httpx.MockTransport
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    calls: int = 0
    _resolved: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.cache_dir = self.cache_dir or (
            Path(os.environ.get("AEGIS_DATA_ROOT", "data")) / "llm_cache"
        )

    # ------------------------------------------------------------------ provider resolution
    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout_s, transport=self.transport)

    def _ollama_up(self) -> bool:
        try:
            check_outbound(self.ollama_url)
            with self._client() as c:
                r = c.get(f"{self.ollama_url}/api/tags", timeout=2.0)
            return r.status_code == 200
        except (httpx.HTTPError, OutboundDeniedError):
            return False

    def resolve_provider(self) -> str | None:
        """Pick the provider once per router; ``None`` means run fully offline."""
        if self._resolved is not None:
            return self._resolved or None
        want = self.provider.lower()
        paid_ok = os.environ.get("AEGIS_ALLOW_PAID_PROVIDERS") == "1"
        candidates = FREE_PROVIDERS if want == "auto" else (want,)
        chosen = ""
        for p in candidates:
            if p == "none":
                break
            if (
                (p == "ollama" and self._ollama_up())
                or (p == "groq" and os.environ.get("GROQ_API_KEY"))
                or (p == "gemini" and os.environ.get("GEMINI_API_KEY"))
                or (p == "anthropic" and paid_ok and os.environ.get("ANTHROPIC_API_KEY"))
                or (p == "openai" and paid_ok and os.environ.get("OPENAI_API_KEY"))
            ):
                chosen = p
            elif (
                p in ("anthropic", "openai")
                and not paid_ok
                and os.environ.get(f"{p.upper()}_API_KEY")
            ):
                log.warning(
                    "%s key present but paid providers are disabled (AEGIS_ALLOW_PAID_PROVIDERS)", p
                )
            if chosen:
                break
        self._resolved = chosen
        return chosen or None

    @property
    def available(self) -> bool:
        return self.resolve_provider() is not None

    @property
    def active_model(self) -> str:
        p = self.resolve_provider() or "none"
        return self.model or DEFAULT_MODELS.get(p, "none")

    @property
    def cost_mode(self) -> str:
        return self.guard.cost_mode

    def describe(self) -> dict[str, Any]:
        return {
            "provider": self.resolve_provider(),
            "model": self.active_model if self.available else None,
            "cost_mode": self.cost_mode,
            "degraded_reason": self.guard.degraded_reason,
            "calls": self.calls,
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost_usd, 6),
        }

    # ------------------------------------------------------------------ caching
    def _cache_key(self, system: str, user: str, model: str) -> str:
        h = hashlib.sha256(f"{model}\x00{self.temperature}\x00{system}\x00{user}".encode())
        return h.hexdigest()

    def _cache_get(self, key: str) -> dict[str, Any] | None:
        assert self.cache_dir is not None
        p = self.cache_dir / f"{key}.json"
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
        return None

    def _cache_put(self, key: str, data: dict[str, Any]) -> None:
        assert self.cache_dir is not None
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.cache_dir / f"{key}.json").write_text(json.dumps(data), encoding="utf-8")

    # ------------------------------------------------------------------ complete
    def complete(self, system: str, user: str, *, model: str | None = None) -> LLMResponse:
        provider = self.resolve_provider()
        if provider is None:
            raise DegradedError("no LLM provider configured")
        model = model or self.active_model
        key = self._cache_key(system, user, f"{provider}:{model}")
        cached = self._cache_get(key)
        if cached is not None:
            self.calls += 1
            return LLMResponse(
                text=cached["text"],
                model=model,
                provider=provider,
                prompt_tokens=cached.get("prompt_tokens", 0),
                completion_tokens=cached.get("completion_tokens", 0),
                cached=True,
            )
        self.guard.check("llm")  # raises DegradedError at a cap; never a paid retry
        t0 = time.perf_counter()
        try:
            resp = self._call_provider(provider, system, user, model)
        except (ProviderError, OutboundDeniedError, httpx.HTTPError) as e:
            self.guard.degrade(f"{provider} unavailable: {type(e).__name__}: {str(e)[:120]}")
            raise DegradedError(str(e)) from e
        resp.seconds = round(time.perf_counter() - t0, 2)
        self.guard.record(tokens=resp.prompt_tokens + resp.completion_tokens, kind="llm")
        self._cache_put(
            key,
            {
                "text": resp.text,
                "prompt_tokens": resp.prompt_tokens,
                "completion_tokens": resp.completion_tokens,
            },
        )
        self.calls += 1
        self.total_cost_usd += resp.cost_usd
        self.total_tokens += resp.prompt_tokens + resp.completion_tokens
        return resp

    def complete_schema(
        self, system: str, user: str, schema: type[T], *, model: str | None = None, retries: int = 1
    ) -> T:
        prompt = user + (
            f"\n\nRespond with ONLY a JSON object matching this schema (no prose, no code fence):\n"
            f"{json.dumps(schema.model_json_schema())}"
        )
        last_err = ""
        for attempt in range(retries + 1):
            resp = self.complete(
                system,
                prompt
                if attempt == 0
                else prompt + f"\n\nYour previous reply was invalid: {last_err}. "
                "Return valid JSON only.",
                model=model,
            )
            try:
                return schema.model_validate_json(_extract_json(resp.text))
            except (ValidationError, ValueError) as e:
                last_err = str(e)[:200]
        raise ValueError(f"LLM did not return valid {schema.__name__}: {last_err}")

    # ------------------------------------------------------------------ providers (httpx only)
    def _call_provider(self, provider: str, system: str, user: str, model: str) -> LLMResponse:
        if provider == "ollama":
            return self._ollama(system, user, model)
        if provider == "groq":
            return self._openai_compatible(
                "https://api.groq.com/openai/v1/chat/completions",
                os.environ["GROQ_API_KEY"],
                system,
                user,
                model,
                provider,
            )
        if provider == "gemini":
            return self._gemini(system, user, model)
        if provider == "openai":
            return self._openai_compatible(
                "https://api.openai.com/v1/chat/completions",
                os.environ["OPENAI_API_KEY"],
                system,
                user,
                model,
                provider,
            )
        if provider == "anthropic":
            return self._anthropic(system, user, model)
        raise ProviderError(f"unknown provider {provider}")

    def _post(self, url: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        check_outbound(url)
        with self._client() as c:
            r = c.post(url, json=body, headers=headers)
        if r.status_code >= 400:
            raise ProviderError(f"HTTP {r.status_code} from {url}: {r.text[:200]}")
        data: dict[str, Any] = r.json()
        return data

    def _ollama(self, system: str, user: str, model: str) -> LLMResponse:
        data = self._post(
            f"{self.ollama_url}/api/chat",
            {
                "model": model,
                "stream": False,
                "format": "json",
                "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            {},
        )
        return LLMResponse(
            text=str((data.get("message") or {}).get("content", "")),
            model=str(data.get("model", model)),
            provider="ollama",
            prompt_tokens=int(data.get("prompt_eval_count") or 0),
            completion_tokens=int(data.get("eval_count") or 0),
            cost_usd=0.0,
        )

    def _openai_compatible(
        self, url: str, key: str, system: str, user: str, model: str, provider: str
    ) -> LLMResponse:
        data = self._post(
            url,
            {
                "model": model,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            {"Authorization": f"Bearer {key}"},
        )
        choice = (data.get("choices") or [{}])[0]
        usage = data.get("usage") or {}
        pt, ct = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
        return LLMResponse(
            text=str((choice.get("message") or {}).get("content") or ""),
            model=str(data.get("model", model)),
            provider=provider,
            prompt_tokens=pt,
            completion_tokens=ct,
            cost_usd=_cost(model, pt, ct) if provider == "openai" else 0.0,
        )

    def _gemini(self, system: str, user: str, model: str) -> LLMResponse:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        data = self._post(
            url,
            {
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {
                    "temperature": self.temperature,
                    "maxOutputTokens": self.max_tokens,
                    "responseMimeType": "application/json",
                },
            },
            {"x-goog-api-key": os.environ["GEMINI_API_KEY"]},
        )
        cands = data.get("candidates") or [{}]
        parts = ((cands[0].get("content") or {}).get("parts")) or [{}]
        usage = data.get("usageMetadata") or {}
        return LLMResponse(
            text=str(parts[0].get("text", "")),
            model=model,
            provider="gemini",
            prompt_tokens=int(usage.get("promptTokenCount") or 0),
            completion_tokens=int(usage.get("candidatesTokenCount") or 0),
            cost_usd=0.0,
        )

    def _anthropic(self, system: str, user: str, model: str) -> LLMResponse:  # pragma: no cover
        data = self._post(
            "https://api.anthropic.com/v1/messages",
            {
                "model": model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            {
                "x-api-key": os.environ["ANTHROPIC_API_KEY"],
                "anthropic-version": "2023-06-01",
            },
        )
        text = "".join(
            b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
        )
        usage = data.get("usage") or {}
        pt, ct = int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0)
        return LLMResponse(
            text=text,
            model=model,
            provider="anthropic",
            prompt_tokens=pt,
            completion_tokens=ct,
            cost_usd=_cost(model, pt, ct),
        )


def _cost(model: str, pt: int, ct: int) -> float:
    inp, out = _PRICES.get(model, (0.0, 0.0))
    return (pt * inp + ct * out) / 1_000_000


def _extract_json(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1:
        return text[start : end + 1]
    return text
