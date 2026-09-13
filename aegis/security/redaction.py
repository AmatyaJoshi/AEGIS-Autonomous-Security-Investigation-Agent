"""PII pseudonymisation before external LLM calls (SPEC §9.5).

Reversible, deterministic mapping: hostnames -> ``HOST-<n>``, usernames -> ``USER-<n>``,
IPs -> ``10.253.<a>.<b>`` (documentation-style), emails -> ``user<n>@example.invalid``. The map is
kept in-memory per investigation and can be persisted locally so a report can be de-pseudonymised
for the analyst. Nothing here reaches an external service.

Phase 1 provides the reversible mapper + detectors; the graph wires it in as a pre-LLM processor in
Phase 3. It is intentionally conservative - it only rewrites tokens it is confident about, so it
never corrupts command lines or hashes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


@dataclass
class Pseudonymizer:
    forward: dict[str, str] = field(default_factory=dict)
    reverse: dict[str, str] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)

    def _token(self, kind: str, value: str, template: str) -> str:
        key = value.lower()
        if key in self.forward:
            return self.forward[key]
        self._counts[kind] = self._counts.get(kind, 0) + 1
        n = self._counts[kind]
        alias = template.format(n=n, a=(n // 254) % 254 + 1, b=n % 254 + 1)
        self.forward[key] = alias
        self.reverse[alias] = value
        return alias

    def host(self, name: str) -> str:
        return self._token("host", name, "HOST-{n}")

    def user(self, name: str) -> str:
        return self._token("user", name, "USER-{n}")

    def ip(self, addr: str) -> str:
        return self._token("ip", addr, "10.253.{a}.{b}")

    def email(self, addr: str) -> str:
        return self._token("email", addr, "user{n}@example.invalid")

    def redact_text(
        self, text: str, *, hosts: list[str] | None = None, users: list[str] | None = None
    ) -> str:
        out = text
        for h in sorted(hosts or [], key=len, reverse=True):
            if h:
                out = re.sub(rf"\b{re.escape(h)}\b", self.host(h), out, flags=re.I)
        for u in sorted(users or [], key=len, reverse=True):
            if u:
                out = re.sub(rf"\b{re.escape(u)}\b", self.user(u), out, flags=re.I)
        out = _EMAIL.sub(lambda m: self.email(m.group(0)), out)
        out = _IPV4.sub(lambda m: self.ip(m.group(0)), out)
        return out

    def restore(self, text: str) -> str:
        out = text
        for alias, value in sorted(self.reverse.items(), key=lambda kv: len(kv[0]), reverse=True):
            out = out.replace(alias, value)
        return out
