"""ATT&CK knowledge base: technique lookup, validation and lightweight description search.

The compact table (``data/techniques.json``, produced by :mod:`aegis.attack.build_kb`) is loaded
once and cached. ``search`` uses a small TF-IDF cosine over technique descriptions - good enough to
justify a mapping in the ``attack_map`` node without pulling in a vector DB. When Postgres+pgvector
is available (SPEC §2.1) the same interface is backed by embeddings; the offline default needs no
services.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA = Path(__file__).parent / "data" / "techniques.json"
_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    parent: str
    is_subtechnique: bool
    tactics: tuple[str, ...]
    tactic_names: tuple[str, ...]
    platforms: tuple[str, ...]
    description: str
    url: str | None


@dataclass
class AttackKB:
    techniques: dict[str, Technique]
    tactics: dict[str, str]
    _idf: dict[str, float] = field(default_factory=dict)
    _vectors: dict[str, dict[str, float]] = field(default_factory=dict)

    # ------------------------------------------------------------------ lookups
    def get(self, technique_id: str) -> Technique | None:
        tid = technique_id.strip().upper()
        return self.techniques.get(tid) or self.techniques.get(tid.split(".")[0])

    def exists(self, technique_id: str) -> bool:
        return self.get(technique_id) is not None

    def validate(self, technique_ids: list[str]) -> tuple[list[str], list[str]]:
        """Return (valid, invalid) technique ids - the attack_map node drops invalid ones."""
        valid: list[str] = []
        invalid: list[str] = []
        for t in technique_ids:
            (valid if self.exists(t) else invalid).append(t.strip().upper())
        return valid, invalid

    def tactics_for(self, technique_id: str) -> list[str]:
        t = self.get(technique_id)
        return list(t.tactics) if t else []

    # ------------------------------------------------------------------ search
    def _ensure_index(self) -> None:
        if self._vectors:
            return
        docs = {tid: _tokenize(f"{t.name} {t.description}") for tid, t in self.techniques.items()}
        df: Counter[str] = Counter()
        for toks in docs.values():
            df.update(set(toks))
        n = len(docs)
        self._idf = {w: math.log(1 + n / c) for w, c in df.items()}
        for tid, toks in docs.items():
            tf = Counter(toks)
            vec = {w: (tf[w] / len(toks)) * self._idf.get(w, 0.0) for w in tf}
            norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
            self._vectors[tid] = {w: v / norm for w, v in vec.items()}

    def search(self, query: str, k: int = 5) -> list[tuple[Technique, float]]:
        self._ensure_index()
        q_toks = _tokenize(query)
        if not q_toks:
            return []
        tf = Counter(q_toks)
        qvec = {w: (tf[w] / len(q_toks)) * self._idf.get(w, 0.0) for w in tf}
        norm = math.sqrt(sum(v * v for v in qvec.values())) or 1.0
        qvec = {w: v / norm for w, v in qvec.items()}
        scored = [
            (tid, sum(qvec.get(w, 0.0) * v for w, v in vec.items()))
            for tid, vec in self._vectors.items()
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [(self.techniques[tid], s) for tid, s in scored[:k] if s > 0]


def _tokenize(text: str) -> list[str]:
    return _WORD.findall(text.lower())


@lru_cache(maxsize=1)
def load_kb(path: str | None = None) -> AttackKB:
    p = Path(path) if path else DATA
    if not p.exists():
        raise FileNotFoundError(
            f"{p} missing - run `python -m aegis.attack.build_kb` to generate the technique table."
        )
    raw: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
    techniques = {
        tid: Technique(
            id=t["id"],
            name=t["name"],
            parent=t["parent"],
            is_subtechnique=t["is_subtechnique"],
            tactics=tuple(t["tactics"]),
            tactic_names=tuple(t["tactic_names"]),
            platforms=tuple(t.get("platforms", [])),
            description=t["description"],
            url=t.get("url"),
        )
        for tid, t in raw["techniques"].items()
    }
    return AttackKB(techniques=techniques, tactics=raw["tactics"])
