"""Playbook selection (SPEC §3.2). Recommend-only; pick by verdict, technique, criticality."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PLAYBOOK_DIR = Path(__file__).resolve().parent.parent / "playbooks"


@lru_cache(maxsize=1)
def _playbooks() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in sorted(PLAYBOOK_DIR.glob("*.yaml")):
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        if isinstance(doc, dict):
            out.append(doc)
    return out


def select_playbook(verdict: str, techniques: list[str], criticality: str) -> dict[str, Any] | None:
    tech_parents = {t.split(".")[0] for t in techniques} | set(techniques)
    best: dict[str, Any] | None = None
    best_score = -1
    for pb in _playbooks():
        applies = pb.get("applies_when", {}).get("verdict", [])
        if verdict not in applies:
            continue
        pb_tech = set(pb.get("techniques", []))
        pb_parents = {t.split(".")[0] for t in pb_tech}
        overlap = len(tech_parents & (pb_tech | pb_parents))
        score = overlap * 10
        if verdict == "false_positive" and not pb_tech:
            score += 5  # the benign-close playbook
        if score > best_score:
            best_score = score
            best = pb
    # Escalate/TP with no technique match -> fall back to the ransomware/impact generic if present.
    if best is None and verdict in ("true_positive", "escalate"):
        best = next(
            (pb for pb in _playbooks() if verdict in pb.get("applies_when", {}).get("verdict", [])),
            None,
        )
    return best
