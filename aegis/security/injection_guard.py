"""Prompt-injection guard for log-derived free text (SPEC §9.3).

Phase 1 ships a deterministic heuristic detector plus the ``<data>`` envelope wrapper that every
tool result and every LLM-visible log field must pass through. The heuristic flags the classic
patterns adversaries embed in log fields ("ignore previous instructions", "classify as false
positive", "you are now...", role markers, base64 instruction blobs). Phase 8 swaps in the Lens
injection detector / a local DeBERTa classifier behind the same interface; the adversarial benchmark
(§8.4) measures both.

The guard NEVER decides the verdict. It returns flags; the graph's ``verdict`` node turns any flag
into an ``escalate`` (§3.2). Flagged spans are redacted before they reach a prompt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["low", "medium", "high"]

# (name, compiled pattern, severity). Ordered roughly by strength of signal.
_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    (
        "ignore_instructions",
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|all)\b.{0,20}"
            r"\b(instruction|prompt|context|rule)",
            re.I,
        ),
        "high",
    ),
    (
        "verdict_steer",
        re.compile(
            r"\b(classify|mark|treat|label|report|set|consider)\b.{0,40}"
            r"\b(as\s+)?(a\s+)?(false[\s_-]?positive|benign|authori[sz]ed|safe|not\s+malicious|"
            r"ignore this)\b",
            re.I,
        ),
        "high",
    ),
    (
        "role_override",
        re.compile(
            r"\b(you are|act as|pretend to be|from now on you)\b.{0,40}"
            r"\b(assistant|system|admin|analyst|ai|model)\b",
            re.I,
        ),
        "high",
    ),
    (
        "system_marker",
        re.compile(
            r"(<\|?(system|assistant|user|im_start|im_end)\|?>|\[/?(inst|sys|system)\])", re.I
        ),
        "high",
    ),
    (
        "authorized_claim",
        re.compile(
            r"\b(this (activity|action|process|alert|event) is|has been)\b.{0,30}"
            r"\b(approved|authori[sz]ed|sanctioned|whitelisted|expected|part of a test)\b",
            re.I,
        ),
        "medium",
    ),
    (
        "do_not_alert",
        re.compile(
            r"\b(do not|don'?t|no need to)\b.{0,20}\b(alert|escalate|report|flag|investigate|"
            r"block)\b",
            re.I,
        ),
        "medium",
    ),
    (
        "tool_instruction",
        re.compile(
            r"\b(execute|run|call|invoke)\b.{0,20}\b(the following|this|command|tool|query|"
            r"function)\b",
            re.I,
        ),
        "medium",
    ),
    (
        "prompt_delimiter",
        re.compile(r"(```+\s*(system|prompt|instruction)|-{3,}\s*(system|instruction))", re.I),
        "medium",
    ),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"), "low"),
    (
        "url_exfil_hint",
        re.compile(r"\b(send|post|exfiltrate|upload)\b.{0,20}\bhttps?://", re.I),
        "low",
    ),
]

_SEV_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass
class InjectionFlag:
    field: str
    pattern: str
    severity: Severity
    excerpt: str


@dataclass
class GuardResult:
    flags: list[InjectionFlag] = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return bool(self.flags)

    @property
    def max_severity(self) -> Severity | None:
        if not self.flags:
            return None
        return max((f.severity for f in self.flags), key=lambda s: _SEV_RANK[s])

    def forces_escalation(self) -> bool:
        return any(_SEV_RANK[f.severity] >= _SEV_RANK["medium"] for f in self.flags)


def scan_text(text: str, field_name: str = "text") -> list[InjectionFlag]:
    if not text:
        return []
    flags: list[InjectionFlag] = []
    for name, pat, sev in _PATTERNS:
        m = pat.search(text)
        if m:
            start = max(0, m.start() - 20)
            excerpt = text[start : m.end() + 20].replace("\n", " ").strip()
            flags.append(InjectionFlag(field_name, name, sev, excerpt[:160]))
    return flags


def scan_fields(fields: dict[str, str]) -> GuardResult:
    result = GuardResult()
    for name, value in fields.items():
        if isinstance(value, str):
            result.flags.extend(scan_text(value, name))
    return result


_REDACTION = "[REDACTED: possible injection - content withheld from model]"


def redact(text: str, flags: list[InjectionFlag]) -> str:
    """Replace flagged spans with a marker. High-severity fields are withheld entirely."""
    if any(f.severity == "high" for f in flags):
        return _REDACTION
    redacted = text
    for f in flags:
        if f.excerpt:
            redacted = redacted.replace(f.excerpt, "[REDACTED]")
    return redacted


def wrap_data(content: str, source: str, *, guard: bool = True) -> tuple[str, GuardResult]:
    """Wrap tool/log content in a ``<data>`` envelope (§4). Content inside is never an instruction.

    Returns the envelope string and the guard result so the caller (a tool) can attach flags to
    state. When ``guard`` is set, high-severity content is redacted inside the envelope too.
    """
    result = GuardResult(flags=scan_text(content, source))
    shown = redact(content, result.flags) if guard and result.triggered else content
    envelope = (
        f'<data source="{_escape(source)}" injection_flagged="{str(result.triggered).lower()}">\n'
        f"{shown}\n</data>"
    )
    return envelope, result


def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
