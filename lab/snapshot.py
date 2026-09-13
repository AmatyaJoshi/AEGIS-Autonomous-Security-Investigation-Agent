"""Parquet snapshots for ``--offline`` mode (SPEC §8.5) and ``aegis lab snapshot``.

A snapshot is a self-contained directory::

    data/snapshots/<name>/
      manifest.json           # name, created, counts, sha256 of every file, git sha, tool versions
      events/dataset=<ds>/*.parquet
      ground_truth/windows.parquet (+ windows.jsonl)
      rules/sigma_pack.jsonl (+ summary)
      org.yaml                 # mock CMDB / IdP used by asset & identity tools

Sources, in order of preference:
1. Elasticsearch ``<prefix>-events-*`` indices (if reachable and ``--from elastic``);
2. the local Parquet staging area ``data/parquet/`` written by loaders (default).

Events are deduplicated on ``event_id`` and re-partitioned by dataset. ``verify()`` re-hashes every
file and re-opens the snapshot with DuckDB so a broken snapshot fails fast in CI.
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
from aegis import __version__
from lab.common.ecs import ARROW_SCHEMA
from lab.emulation.ground_truth import GroundTruthTable

log = logging.getLogger(__name__)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_sha(repo: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _consolidate_events(src_glob: str, dest: Path) -> dict[str, int]:
    """Dedupe on event_id and write one zstd Parquet per dataset partition (row-grouped)."""
    con = duckdb.connect(database=":memory:")
    con.execute(
        f"CREATE VIEW src AS SELECT * FROM read_parquet('{src_glob}', hive_partitioning=true, "
        "union_by_name=true)"
    )
    datasets = [r[0] for r in con.execute("SELECT DISTINCT dataset FROM src ORDER BY 1").fetchall()]
    counts: dict[str, int] = {}
    cols = ", ".join(f'"{f.name}"' for f in ARROW_SCHEMA)
    for ds in datasets:
        out_dir = dest / "events" / f"dataset={ds}"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "part-0000.parquet"
        con.execute(
            f"COPY (SELECT {cols} FROM (SELECT *, row_number() OVER (PARTITION BY event_id "
            f'ORDER BY "@timestamp") AS rn FROM src WHERE dataset = ?) WHERE rn = 1 '
            f"ORDER BY \"@timestamp\") TO '{out.as_posix()}' (FORMAT PARQUET, COMPRESSION ZSTD, "
            "ROW_GROUP_SIZE 100000)",
            [ds],
        )
        counts[ds] = int(pq.read_metadata(out).num_rows)
    con.close()
    return counts


def _events_from_elastic(dest: Path, settings: Any) -> dict[str, int]:
    """Scroll every ``<prefix>-events-*`` index into Parquet (read-only key suffices)."""
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import scan

    kwargs: dict[str, Any] = {}
    key = settings.readonly_api_key or settings.writer_api_key
    if key is not None:
        kwargs["api_key"] = key.get_secret_value()
    elif settings.username and settings.password is not None:
        kwargs["basic_auth"] = (settings.username, settings.password.get_secret_value())
    es = Elasticsearch(settings.url, verify_certs=settings.verify_certs, **kwargs)
    staging = dest / "_staging"
    staging.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for idx in es.indices.get(index=f"{settings.index_prefix}-events-*"):
        ds = idx.rsplit("-", 1)[-1]
        rows: list[dict[str, Any]] = []
        n = 0
        part = 0
        for hit in scan(es, index=idx, query={"query": {"match_all": {}}}, size=5000):
            rows.append(_es_doc_to_row(hit["_id"], hit["_source"]))
            if len(rows) >= 100_000:
                _write_part(rows, staging / f"dataset={ds}", part)
                n += len(rows)
                rows, part = [], part + 1
        if rows:
            _write_part(rows, staging / f"dataset={ds}", part)
            n += len(rows)
        counts[ds] = n
    es.close()
    consolidated = _consolidate_events((staging / "**" / "*.parquet").as_posix(), dest)
    shutil.rmtree(staging)
    return consolidated


def _write_part(rows: list[dict[str, Any]], out_dir: Path, part: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows, schema=ARROW_SCHEMA)
    pq.write_table(table, out_dir / f"part-{part:04d}.parquet", compression="zstd")


def _es_doc_to_row(event_id: str, src: dict[str, Any]) -> dict[str, Any]:
    from lab.common.ecs import ECS_PATHS

    def get(path: str) -> Any:
        cur: Any = src
        for p in path.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
        return cur

    row: dict[str, Any] = {
        "event_id": event_id,
        "@timestamp": src.get("@timestamp"),
        "raw": (src.get("aegis") or {}).get("raw", "{}"),
    }
    for attr, path in ECS_PATHS.items():
        row[attr] = get(path)
    row["tags"] = row.get("tags") or []
    return row


def create_snapshot(
    *,
    name: str,
    data_root: Path,
    repo_root: Path,
    source: str = "parquet",
    elastic_settings: Any | None = None,
    org_yaml: Path | None = None,
) -> Path:
    dest = data_root / "snapshots" / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    if source == "elastic":
        if elastic_settings is None:
            raise ValueError("elastic_settings required for source=elastic")
        counts = _events_from_elastic(dest, elastic_settings)
    else:
        staging = data_root / "parquet" / "events"
        if not any(staging.rglob("*.parquet")):
            raise FileNotFoundError(
                f"no staged Parquet under {staging}; run `aegis lab load` first"
            )
        counts = _consolidate_events((staging / "**" / "*.parquet").as_posix(), dest)

    gt_dir = dest / "ground_truth"
    gt_dir.mkdir()
    gt = GroundTruthTable(data_root / "ground_truth")
    if gt.jsonl.exists():
        shutil.copy(gt.jsonl, gt_dir / "windows.jsonl")
        gt.to_parquet(gt_dir / "windows.parquet")
    coverage = gt.coverage()

    rules_src = data_root / "rules"
    if rules_src.exists():
        (dest / "rules").mkdir()
        for f in rules_src.glob("sigma_pack*"):
            shutil.copy(f, dest / "rules" / f.name)

    if org_yaml and org_yaml.exists():
        shutil.copy(org_yaml, dest / "org.yaml")

    files = {
        p.relative_to(dest).as_posix(): {"sha256": _sha256(p), "bytes": p.stat().st_size}
        for p in sorted(dest.rglob("*"))
        if p.is_file()
    }
    manifest = {
        "name": name,
        "created": datetime.now(tz=UTC).isoformat(),
        "aegis_version": __version__,
        "git_sha": _git_sha(repo_root),
        "python": platform.python_version(),
        "source": source,
        "events": counts,
        "events_total": sum(counts.values()),
        "ground_truth": coverage,
        "files": files,
    }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return dest


def verify_snapshot(path: Path) -> dict[str, Any]:
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    problems: list[str] = []
    for rel, meta in manifest["files"].items():
        p = path / rel
        if not p.exists():
            problems.append(f"missing {rel}")
        elif _sha256(p) != meta["sha256"]:
            problems.append(f"hash mismatch {rel}")
    total = -1
    stats: dict[str, Any] = {}
    if not problems:
        # Only re-open with DuckDB when every file hashes clean; a tampered file would just raise.
        from aegis.siem.duckdb import DuckDBSiem

        siem = DuckDBSiem(path)
        try:
            total = siem.count()
            if total != manifest["events_total"]:
                problems.append(f"event count {total} != manifest {manifest['events_total']}")
            stats = siem.stats()
        finally:
            siem.close()
    return {
        "ok": not problems,
        "problems": problems,
        "events_total": total,
        "datasets": stats,
        "ground_truth": manifest.get("ground_truth", {}),
    }
