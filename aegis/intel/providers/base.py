"""Threat-intel provider interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

Observable = Literal["ip", "domain", "hash", "url", "unknown"]


@dataclass
class IntelVerdict:
    observable: str
    observable_type: Observable
    provider: str
    verdict: Literal["malicious", "suspicious", "benign", "unknown"]
    score: float  # 0-1, higher = more malicious
    first_seen: str | None = None
    last_seen: str | None = None
    categories: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observable": self.observable,
            "type": self.observable_type,
            "provider": self.provider,
            "verdict": self.verdict,
            "score": round(self.score, 3),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "categories": self.categories,
            **self.detail,
        }


class IntelProvider(Protocol):
    name: str

    def lookup(self, observable: str, observable_type: Observable) -> IntelVerdict: ...
