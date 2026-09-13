"""LLM router (SPEC §2.1 LiteLLM tier): provider selection, JSON-schema parsing, caching, cost.

Providers are tried in configured order. The default is fully offline: if no API key is present the
router reports ``available == False`` and the graph uses the deterministic ``HeuristicReasoner``
instead (so nothing here is required to run the pipeline). When a key is present, ``complete``:

* renders messages, calls the provider (Anthropic / OpenAI via their SDKs, or LiteLLM if installed);
* caches responses by content hash (SPEC §8.5) so benchmark reruns are deterministic and free;
* parses/validates the response into a Pydantic schema, retrying once on failure;
* accumulates token + USD cost per call for the telemetry span attributes (§10).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

# Rough public prices (USD per 1M tokens) for cost accounting; override via env if needed.
_PRICES: dict[str, tuple[float, float]] = {
    "claude-fable-5-1": (3.0, 15.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "gpt-4o": (2.5, 10.0),
    "gpt-4o-mini": (0.15, 0.6),
}


@dataclass
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    cached: bool = False


@dataclass
class LLMRouter:
    model: str = field(
        default_factory=lambda: os.environ.get("AEGIS_LLM_MODEL", "claude-fable-5-1")
    )
    fallback_model: str | None = field(
        default_factory=lambda: os.environ.get("AEGIS_LLM_FALLBACK", "gpt-4o-mini")
    )
    temperature: float = 0.0
    cache_dir: Path | None = None
    max_tokens: int = 2048
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    calls: int = 0

    def __post_init__(self) -> None:
        self.cache_dir = self.cache_dir or (Path("data") / "llm_cache")

    @property
    def available(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"))

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
        model = model or self.model
        key = self._cache_key(system, user, model)
        cached = self._cache_get(key)
        if cached is not None:
            self.calls += 1
            return LLMResponse(
                text=cached["text"],
                model=model,
                prompt_tokens=cached.get("prompt_tokens", 0),
                completion_tokens=cached.get("completion_tokens", 0),
                cached=True,
            )
        resp = self._call_provider(system, user, model)
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

    def _call_provider(self, system: str, user: str, model: str) -> LLMResponse:
        if model.startswith("claude") and os.environ.get("ANTHROPIC_API_KEY"):
            return self._anthropic(system, user, model)
        if model.startswith("gpt") and os.environ.get("OPENAI_API_KEY"):
            return self._openai(system, user, model)
        # Try any available provider as a fallback.
        if os.environ.get("ANTHROPIC_API_KEY"):
            return self._anthropic(system, user, "claude-fable-5-1")
        if os.environ.get("OPENAI_API_KEY"):
            return self._openai(system, user, "gpt-4o-mini")
        raise RuntimeError("no LLM provider configured (set ANTHROPIC_API_KEY or OPENAI_API_KEY)")

    def _anthropic(self, system: str, user: str, model: str) -> LLMResponse:  # pragma: no cover
        import anthropic

        client = anthropic.Anthropic()
        msg = client.messages.create(
            model=model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(b.text for b in msg.content if b.type == "text")
        pt, ct = msg.usage.input_tokens, msg.usage.output_tokens
        return LLMResponse(
            text=text,
            model=model,
            prompt_tokens=pt,
            completion_tokens=ct,
            cost_usd=_cost(model, pt, ct),
        )

    def _openai(self, system: str, user: str, model: str) -> LLMResponse:  # pragma: no cover
        import openai

        client = openai.OpenAI()
        msg = client.chat.completions.create(
            model=model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        text = msg.choices[0].message.content or ""
        pt = msg.usage.prompt_tokens if msg.usage else 0
        ct = msg.usage.completion_tokens if msg.usage else 0
        return LLMResponse(
            text=text,
            model=model,
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
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return text
