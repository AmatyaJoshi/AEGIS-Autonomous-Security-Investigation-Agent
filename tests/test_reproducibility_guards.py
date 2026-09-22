"""Guards added after the Phase 0 fresh-clone verification (STATUS.md B1, B3).

B1: a dependency drift (pyparsing 3.3.3) silently dropped Sigma conversion to 40/377 with exit 0.
B3: `bench build` rewrote the *frozen* manifest on every run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bench.build_benchmark import write_frozen_manifest
from lab.rules.convert import conversion_floor_breach


def _summary(esql: int, spl: int, total: int = 377) -> dict[str, int]:
    return {"rules_total": total, "esql_ok": esql, "spl_ok": spl}


def test_conversion_floor_passes_on_healthy_pack() -> None:
    # The committed pack: 367/377 ES|QL, 377/377 SPL.
    assert conversion_floor_breach(_summary(367, 377)) is None


def test_conversion_floor_catches_pyparsing_regression() -> None:
    # What a fresh install with pyparsing 3.3.3 produced.
    reason = conversion_floor_breach(_summary(258, 40))
    assert reason is not None
    assert "esql_ok=258/377" in reason
    assert "spl_ok=40/377" in reason


def test_conversion_floor_respects_threshold_and_empty_pack() -> None:
    assert conversion_floor_breach(_summary(300, 377), min_rate=0.7) is None
    assert conversion_floor_breach(_summary(300, 377), min_rate=0.9) is not None
    assert conversion_floor_breach({"rules_total": 0}) == "no rules selected"


def _frozen(h: str, created: str) -> dict[str, object]:
    return {"version": "v1", "created": created, "manifest_hash": h, "entries": []}


def test_frozen_manifest_not_rewritten_when_hash_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "benchmark_v1.frozen.json"
    assert write_frozen_manifest(_frozen("abc", "2026-09-13T00:00:00+00:00"), path) is True
    before = path.read_text(encoding="utf-8")
    # Same alert set, later timestamp: must be a no-op.
    assert write_frozen_manifest(_frozen("abc", "2026-09-21T00:00:00+00:00"), path) is False
    assert path.read_text(encoding="utf-8") == before
    assert json.loads(before)["created"] == "2026-09-13T00:00:00+00:00"


def test_frozen_manifest_refuses_silent_content_change(tmp_path: Path) -> None:
    path = tmp_path / "benchmark_v1.frozen.json"
    write_frozen_manifest(_frozen("abc", "2026-09-13T00:00:00+00:00"), path)
    with pytest.raises(RuntimeError, match="Bump BENCH_VERSION"):
        write_frozen_manifest(_frozen("def", "2026-09-21T00:00:00+00:00"), path)
    assert json.loads(path.read_text(encoding="utf-8"))["manifest_hash"] == "abc"
