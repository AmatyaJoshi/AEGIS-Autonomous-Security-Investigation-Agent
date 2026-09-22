"""Zero-cost guards for every outbound LLM / external-API call (COST.md).

Three things live here because they are enforced together:

* **Budget caps** from ``BUDGET_*`` environment variables with free-tier-safe defaults. A per-run
  call cap and a per-day token cap (persisted in a small JSON file so restarts do not reset it).
* **Degraded mode**: when a cap is reached the guard flips to ``cost_mode == "degraded"`` and the
  caller falls back to the deterministic path (``HeuristicReasoner`` / ``LocalStore``). It never
  raises out of the graph and never retries against a paid provider.
* **Outbound allow-list**: every host an LLM/API client may contact. Anything else fails closed
  before a socket is opened. The list is logged at startup so a reviewer can audit it in one line.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("aegis.budget")

# Hosts that any AEGIS component is allowed to reach. Local Ollama is matched by scheme/host below.
OUTBOUND_ALLOWLIST: tuple[str, ...] = (
    "api.groq.com",  # Groq free tier (LLM fallback)
    "generativelanguage.googleapis.com",  # Gemini free tier (LLM fallback)
    "pulse.evorozen.com",  # Evorozen Neural Pulse (case memory, Phase 1)
    "raw.githubusercontent.com",  # public datasets (lab loaders only)
    "codeload.github.com",
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
)
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal", "ollama")


class DegradedError(RuntimeError):
    """Raised by the router when a budget cap or provider outage forces the deterministic path."""


class OutboundDeniedError(RuntimeError):
    """Raised before any request to a host that is not on the allow-list (fail closed)."""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def check_outbound(url: str) -> str:
    """Return the host if ``url`` may be contacted, else raise :class:`OutboundDeniedError`."""
    host = (urlparse(url).hostname or "").lower()
    extra = tuple(h.strip().lower() for h in os.environ.get("AEGIS_OUTBOUND_EXTRA", "").split(","))
    if host in _LOCAL_HOSTS or host in OUTBOUND_ALLOWLIST or (host and host in extra):
        return host
    raise OutboundDeniedError(f"outbound host {host!r} is not on the allow-list (COST.md)")


def log_allowlist() -> None:
    """One startup line listing every host this process may contact."""
    ollama = os.environ.get("AEGIS_OLLAMA_URL", "http://localhost:11434")
    log.info(
        "outbound allow-list: %s + local ollama (%s); anything else fails closed",
        ", ".join(OUTBOUND_ALLOWLIST),
        ollama,
    )


@dataclass
class BudgetGuard:
    """Per-run and per-day caps. ``record`` after each successful call; ``check`` before."""

    calls_per_run: int = field(default_factory=lambda: _env_int("BUDGET_LLM_CALLS_PER_RUN", 60))
    tokens_per_day: int = field(
        default_factory=lambda: _env_int("BUDGET_LLM_TOKENS_PER_DAY", 300_000)
    )
    external_calls_per_day: int = field(
        default_factory=lambda: _env_int("BUDGET_EXTERNAL_CALLS_PER_DAY", 2_000)
    )
    state_path: Path = field(
        default_factory=lambda: Path(os.environ.get("AEGIS_DATA_ROOT", "data")) / "budget.json"
    )
    run_calls: int = 0
    degraded_reason: str | None = None

    # ------------------------------------------------------------------ persistence
    def _load(self) -> dict[str, int | str]:
        data: dict[str, int | str] = {}
        try:
            loaded = json.loads(self.state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError):
            pass
        today = datetime.now(tz=UTC).date().isoformat()
        if data.get("day") != today:
            data = {"day": today, "tokens": 0, "external_calls": 0}
        return data

    def _save(self, data: dict[str, int | str]) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:  # pragma: no cover - read-only FS; degrade gracefully, never crash
            log.warning("budget state not persisted at %s", self.state_path)

    # ------------------------------------------------------------------ API
    @property
    def cost_mode(self) -> str:
        return "degraded" if self.degraded_reason else "normal"

    def snapshot(self) -> dict[str, int | str | None]:
        data = self._load()
        return {
            "cost_mode": self.cost_mode,
            "degraded_reason": self.degraded_reason,
            "run_calls": self.run_calls,
            "calls_per_run": self.calls_per_run,
            "tokens_today": int(data.get("tokens", 0)),
            "tokens_per_day": self.tokens_per_day,
            "external_calls_today": int(data.get("external_calls", 0)),
            "external_calls_per_day": self.external_calls_per_day,
        }

    def check(self, kind: str = "llm") -> None:
        """Raise :class:`DegradedError` if the next call would exceed a cap."""
        data = self._load()
        if kind == "llm":
            if self.run_calls >= self.calls_per_run:
                self._degrade(f"per-run LLM call cap reached ({self.calls_per_run})")
            if int(data.get("tokens", 0)) >= self.tokens_per_day:
                self._degrade(f"per-day LLM token cap reached ({self.tokens_per_day})")
        if int(data.get("external_calls", 0)) >= self.external_calls_per_day:
            self._degrade(f"per-day external call cap reached ({self.external_calls_per_day})")

    def record(self, *, tokens: int = 0, kind: str = "llm") -> None:
        data = self._load()
        if kind == "llm":
            self.run_calls += 1
            data["tokens"] = int(data.get("tokens", 0)) + max(0, tokens)
        data["external_calls"] = int(data.get("external_calls", 0)) + 1
        self._save(data)

    def degrade(self, reason: str) -> None:
        """Enter degraded mode for a non-budget reason (provider unreachable, bad output)."""
        if not self.degraded_reason:
            log.warning("cost_mode -> degraded: %s", reason)
        self.degraded_reason = reason

    def _degrade(self, reason: str) -> None:
        self.degrade(reason)
        raise DegradedError(reason)


_GUARD: BudgetGuard | None = None


def get_guard() -> BudgetGuard:
    """Process-wide guard so the API, CLI and graph share one budget."""
    global _GUARD
    if _GUARD is None:
        _GUARD = BudgetGuard()
    return _GUARD


def reset_guard() -> BudgetGuard:
    """Tests and ``make demo`` start from a clean per-run counter."""
    global _GUARD
    _GUARD = BudgetGuard()
    return _GUARD
