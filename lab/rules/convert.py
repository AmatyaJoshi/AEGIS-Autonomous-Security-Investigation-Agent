"""Download the SigmaHQ release bundle, curate a pack, convert to ES|QL and SPL.

Output (``data/rules/``):
* ``sigma_pack.jsonl`` - one record per selected rule: id, title, description, level, status,
  logsource, tags, techniques, the original YAML, ``esql`` and ``spl`` conversions (or the error).
* ``sigma_pack.summary.json`` - counts, per-logsource conversion success, error histogram.

These records are exactly the (NL, query) aligned pairs §7.2 trains on, so this module is shared by
``lab`` and ``training/query_gen/build_pairs.py``.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PACK_YAML = Path(__file__).with_name("pack.yaml")


class SigmaRuleRecord(BaseModel):
    id: str
    title: str
    description: str | None = None
    level: str = "medium"
    status: str = "test"
    logsource: dict[str, str]
    tags: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    path: str
    yaml: str
    esql: str | None = None
    esql_error: str | None = None
    spl: str | None = None
    spl_error: str | None = None
    holdout: bool = False


def load_pack_config(path: Path = PACK_YAML) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def download_bundle(dest: Path, url: str, client: httpx.Client | None = None) -> Path:
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    client = client or httpx.Client(timeout=300, follow_redirects=True)
    with client.stream("GET", url) as r:
        r.raise_for_status()
        with dest.open("wb") as f:
            for chunk in r.iter_bytes():
                f.write(chunk)
    return dest


def iter_rules(bundle: Path) -> Iterator[tuple[str, str, dict[str, Any]]]:
    with zipfile.ZipFile(bundle) as z:
        for name in sorted(z.namelist()):
            if not name.endswith((".yml", ".yaml")) or "/deprecated/" in name:
                continue
            text = io.TextIOWrapper(z.open(name), encoding="utf-8").read()
            try:
                docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
            except yaml.YAMLError as e:
                log.warning("bad yaml %s: %s", name, e)
                continue
            for doc in docs:
                if "detection" in doc and "logsource" in doc:
                    yield name, text, doc


def _matches(logsource: dict[str, Any], wanted: list[dict[str, str]]) -> bool:
    return any(
        all(str(logsource.get(k, "")).lower() == v.lower() for k, v in w.items()) for w in wanted
    )


def select_rules(bundle: Path, cfg: dict[str, Any]) -> list[SigmaRuleRecord]:
    sel = cfg["selection"]
    min_level = LEVELS[sel.get("min_level", "medium")]
    statuses = set(sel.get("statuses", ["stable", "test"]))
    wanted = sel["logsources"]
    holdout = set(sel.get("holdout_categories", []))
    out: list[SigmaRuleRecord] = []
    for path, text, doc in iter_rules(bundle):
        ls = {k: str(v) for k, v in (doc.get("logsource") or {}).items()}
        is_holdout = ls.get("category") in holdout
        if not is_holdout and not _matches(ls, wanted):
            continue
        level = str(doc.get("level", "medium")).lower()
        status = str(doc.get("status", "test")).lower()
        if not is_holdout and (LEVELS.get(level, 0) < min_level or status not in statuses):
            continue
        tags = [str(t) for t in doc.get("tags") or []]
        techniques = [
            t.split(".", 1)[1].upper()
            for t in tags
            if t.startswith("attack.t") and t[8:9].isdigit()
        ]
        tactics = [
            t.split(".", 1)[1]
            for t in tags
            if t.startswith("attack.") and t[7:8] != "t" and "." not in t[7:]
        ]
        out.append(
            SigmaRuleRecord(
                id=str(doc.get("id", path)),
                title=str(doc.get("title", "")),
                description=doc.get("description"),
                level=level,
                status=status,
                logsource=ls,
                tags=tags,
                techniques=techniques,
                tactics=tactics,
                path=path,
                yaml=text,
                holdout=is_holdout,
            )
        )
    # rank: critical > high > medium; stable before test; then title
    out.sort(key=lambda r: (-LEVELS.get(r.level, 0), r.status != "stable", r.title))
    max_rules = int(sel.get("max_rules", 320))
    core = [r for r in out if not r.holdout][:max_rules]
    return core + [r for r in out if r.holdout]


def convert_rules(records: list[SigmaRuleRecord]) -> list[SigmaRuleRecord]:
    """Attach ES|QL and SPL conversions in place. Errors are recorded per rule."""
    from sigma.backends.elasticsearch import ESQLBackend
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    from sigma.pipelines.elasticsearch import ecs_windows
    from sigma.pipelines.sysmon import sysmon_pipeline
    from sigma.pipelines.windows import windows_logsource_pipeline
    from sigma.processing.pipeline import ProcessingPipeline

    esql = ESQLBackend(
        processing_pipeline=ProcessingPipeline() + windows_logsource_pipeline() + ecs_windows()
    )
    spl = SplunkBackend(
        processing_pipeline=ProcessingPipeline() + sysmon_pipeline() + windows_logsource_pipeline()
    )
    for rec in records:
        try:
            coll = SigmaCollection.from_yaml(rec.yaml)
        except Exception as e:
            rec.esql_error = rec.spl_error = f"parse: {type(e).__name__}: {e}"[:300]
            continue
        try:
            rec.esql = esql.convert(coll)[0]
        except Exception as e:
            rec.esql_error = f"{type(e).__name__}: {e}"[:300]
        try:
            rec.spl = spl.convert(coll)[0]
        except Exception as e:
            rec.spl_error = f"{type(e).__name__}: {e}"[:300]
    return records


def write_pack(records: list[SigmaRuleRecord], out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "sigma_pack.jsonl").open("w", encoding="utf-8") as f:
        for r in records:
            f.write(r.model_dump_json() + "\n")
    core = [r for r in records if not r.holdout]
    per_ls: dict[str, dict[str, int]] = {}
    for r in records:
        key = "/".join(f"{k}={v}" for k, v in sorted(r.logsource.items()))
        d = per_ls.setdefault(key, {"rules": 0, "esql_ok": 0, "spl_ok": 0})
        d["rules"] += 1
        d["esql_ok"] += r.esql is not None
        d["spl_ok"] += r.spl is not None
    summary = {
        "rules_total": len(records),
        "rules_core": len(core),
        "rules_holdout": len(records) - len(core),
        "esql_ok": sum(r.esql is not None for r in records),
        "spl_ok": sum(r.spl is not None for r in records),
        "techniques": len({t for r in core for t in r.techniques}),
        "levels": dict(Counter(r.level for r in core)),
        "esql_errors": dict(
            Counter(
                (r.esql_error or "").split(":")[0] for r in records if r.esql_error
            ).most_common(10)
        ),
        "spl_errors": dict(
            Counter((r.spl_error or "").split(":")[0] for r in records if r.spl_error).most_common(
                10
            )
        ),
        "per_logsource": per_ls,
    }
    (out_dir / "sigma_pack.summary.json").write_text(json.dumps(summary, indent=1))
    return summary


def read_pack(out_dir: Path) -> list[SigmaRuleRecord]:
    path = out_dir / "sigma_pack.jsonl"
    with path.open(encoding="utf-8") as f:
        return [SigmaRuleRecord.model_validate_json(line) for line in f if line.strip()]


def build_pack(raw_dir: Path, out_dir: Path, cfg_path: Path = PACK_YAML) -> dict[str, Any]:
    cfg = load_pack_config(cfg_path)
    url = cfg["source"]["release_url"]
    if cfg["source"].get("pinned_tag"):
        url = url.replace("/latest/download/", f"/download/{cfg['source']['pinned_tag']}/")
    bundle = download_bundle(raw_dir / "sigma_core++.zip", url)
    records = convert_rules(select_rules(bundle, cfg))
    return write_pack(records, out_dir)
