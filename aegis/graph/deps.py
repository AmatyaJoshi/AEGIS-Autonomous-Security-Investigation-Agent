"""Dependencies injected into the investigation graph nodes.

Bundling the SIEM adapter, reasoner, query generator, optional triage model and the org model lets
node functions be pure closures over ``Deps`` - easy to build for a live run, an offline benchmark
or a unit test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from aegis.graph.reasoner import Reasoner
from aegis.intel.providers.base import IntelProvider
from aegis.intel.providers.offline import OfflineProvider
from aegis.models.query_gen import QueryGenerator
from aegis.siem.base import SiemAdapter


class TriageModel(Protocol):
    name: str

    def score(self, features: dict[str, Any]) -> dict[str, float]:
        """Return {'p_tp':..,'p_fp':..,'p_escalate':..}."""
        ...


@dataclass
class Deps:
    siem: SiemAdapter
    reasoner: Reasoner
    generator: QueryGenerator = field(default_factory=QueryGenerator)
    intel: IntelProvider = field(default_factory=OfflineProvider)
    triage: TriageModel | None = None
    org_path: str | None = None
    pack_path: str | None = None
    intel_cache_dir: Path | None = None
    fast_path_pfp: float = 0.97
    review_mode: bool = False
    business_hours: tuple[int, int] = (8, 19)
