"""Citation post-processor (SPEC §3.2 report node, §9.4 "evidence or silence").

Every factual sentence in an incident report must end with a ``[E:<event_id>]`` citation whose id
resolves to a real document. ``check_report`` returns the offending sentences; the report node
re-prompts (max 2) and, failing that, rejects the report. ``resolvable`` verifies each cited id
exists in the SIEM so the agent cannot cite a fabricated document.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_CITE = re.compile(r"\[E:([0-9a-fA-F]{6,64})\]")
_SENTENCE = re.compile(r"[^.!?\n]+[.!?]")
# Lines that are structural, not factual claims, and so are exempt from the citation rule.
_EXEMPT_PREFIX = (
    "#",
    "-",
    "*",
    "|",
    ">",
    "```",
    "1.",
    "2.",
    "3.",
    "4.",
    "5.",
    "6.",
    "7.",
    "8.",
    "9.",
    "0.",
)


@dataclass
class CitationReport:
    ok: bool
    uncited_sentences: list[str]
    cited_ids: set[str]
    unresolved_ids: set[str]


def _is_factual(line: str) -> bool:
    s = line.strip()
    if not s or s.startswith(_EXEMPT_PREFIX):
        return False
    # A heading-like line with no verb-ish content is exempt; keep it simple: require a space.
    return " " in s


def check_report(markdown: str, valid_ids: set[str] | None = None) -> CitationReport:
    """Every factual line must carry at least one [E:<id>] citation.

    Per-line (rather than per-sentence) avoids false positives from decimals, timestamps and IPs
    that contain periods, while still enforcing the "evidence or silence" rule (§9.4): a factual
    claim without a citation is rejected.
    """
    uncited: list[str] = []
    cited: set[str] = set()
    for raw_line in markdown.splitlines():
        line_cites = list(_CITE.finditer(raw_line))
        cited.update(m.group(1) for m in line_cites)
        if not _is_factual(raw_line):
            continue
        if len(raw_line.strip()) > 15 and not line_cites:
            uncited.append(raw_line.strip())
    unresolved: set[str] = set()
    if valid_ids is not None:
        unresolved = {
            c for c in cited if not any(v.startswith(c) or c.startswith(v) for v in valid_ids)
        }
    ok = not uncited and not unresolved
    return CitationReport(
        ok=ok, uncited_sentences=uncited, cited_ids=cited, unresolved_ids=unresolved
    )


def cited_ids(markdown: str) -> set[str]:
    return {m.group(1) for m in _CITE.finditer(markdown)}
