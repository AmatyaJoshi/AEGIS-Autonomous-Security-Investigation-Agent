"""Threat-intel cache (SPEC §4, §8.5). Content-addressed, JSON-on-disk, offline-frozen.

Every TI lookup is cached by ``(provider, observable)`` so the benchmark and ``--offline`` mode make
zero external calls. In offline mode a frozen cache is the only source; a miss returns a neutral
"unknown" verdict rather than reaching out.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class IntelCache:
    root: Path
    offline: bool = False
    _mem: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, provider: str, observable: str) -> Path:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in observable)[:120]
        return self.root / provider / f"{safe}.json"

    def get(self, provider: str, observable: str) -> dict[str, Any] | None:
        key = f"{provider}:{observable}"
        if key in self._mem:
            return self._mem[key]
        p = self._path(provider, observable)
        if p.exists():
            data: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
            self._mem[key] = data
            return data
        return None

    def put(self, provider: str, observable: str, data: dict[str, Any]) -> None:
        key = f"{provider}:{observable}"
        self._mem[key] = data
        p = self._path(provider, observable)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({**data, "_cached_at": time.time()}, indent=1), encoding="utf-8")
