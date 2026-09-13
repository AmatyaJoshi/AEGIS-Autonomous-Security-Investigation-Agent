"""attack_kb tool: technique/tactic search and validation over the local ATT&CK KB (SPEC §4)."""

from __future__ import annotations

from typing import Any

from aegis.attack.kb import load_kb
from aegis.tools.base import ToolResult, make_result


def attack_kb(query: str, k: int = 5) -> ToolResult:
    kb = load_kb()
    # Direct technique id lookup takes precedence.
    direct = kb.get(query) if query.strip().upper().startswith("T") else None
    data: dict[str, Any]
    if direct is not None:
        data = {
            "query": query,
            "match": "exact",
            "technique": {
                "id": direct.id,
                "name": direct.name,
                "tactics": list(direct.tactics),
                "tactic_names": list(direct.tactic_names),
                "platforms": list(direct.platforms),
                "description": direct.description,
                "url": direct.url,
            },
        }
        render = (
            f"{direct.id} {direct.name}\ntactics: {', '.join(direct.tactic_names)}\n"
            f"{direct.description[:400]}"
        )
        return make_result("attack_kb", "attack_kb", data, render=render, guard=False)
    results = kb.search(query, k=k)
    data = {
        "query": query,
        "match": "search",
        "results": [
            {
                "id": t.id,
                "name": t.name,
                "tactics": list(t.tactic_names),
                "score": round(s, 3),
                "description": t.description[:300],
            }
            for t, s in results
        ],
    }
    render = (
        "\n".join(f"{t.id} {t.name} ({s:.2f}) - {', '.join(t.tactic_names)}" for t, s in results)
        or "no matches"
    )
    return make_result("attack_kb", "attack_kb", data, render=render, guard=False)


def validate_techniques(technique_ids: list[str]) -> tuple[list[str], list[str]]:
    return load_kb().validate(technique_ids)
