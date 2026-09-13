"""sigma_match tool: run the curated rule pack against a single event (SPEC §4).

Given an event id (resolved via the SIEM adapter) or an inline event row, returns every Sigma rule
that fires plus its techniques - the ``context`` node uses this to re-match the raw event and the
``attack_map`` node uses the rule tags as technique candidates.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from aegis.schema.normalize.sigma_match import SigmaRuleset
from aegis.tools.base import ToolResult, make_result

DEFAULT_PACK = Path("data") / "rules" / "sigma_pack.jsonl"


@lru_cache(maxsize=2)
def _ruleset(pack: str) -> SigmaRuleset:
    return SigmaRuleset.from_pack(pack)


def sigma_match(event: dict[str, Any], *, pack_path: str | None = None) -> ToolResult:
    rs = _ruleset(str(pack_path or DEFAULT_PACK))
    matches = rs.match_event(event)
    data = {
        "event_id": event.get("event_id"),
        "rules_evaluated": len(rs),
        "matches": [
            {
                "rule_id": m.rule_id,
                "title": m.title,
                "level": m.level,
                "techniques": list(m.techniques),
                "tactics": list(m.tactics),
                "matched_fields": list(m.matched_fields),
            }
            for m in matches
        ],
    }
    render = (
        "\n".join(
            f"{m.level.upper():8} {m.title} [{', '.join(m.techniques) or '-'}]" for m in matches
        )
        or "no rules matched"
    )
    return make_result("sigma_match", "sigma_pack", data, render=render, guard=False)
