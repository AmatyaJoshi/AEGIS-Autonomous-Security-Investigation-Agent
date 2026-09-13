"""OTRF Security-Datasets (formerly Mordor) loader.

Source: https://github.com/OTRF/Security-Datasets - ``datasets/atomic/_metadata/*.yaml`` describe
each dataset (title, platform, ``attack_mappings`` with technique / sub-technique / tactics, and the
zip ``files``). Zips contain newline-delimited JSON Windows events (Sysmon, Security, PowerShell...)
already flattened by the OTRF collection pipeline.

Ground truth: every event in a dataset zip is adversary-emulation telemetry for the techniques in
its metadata, so one ``GroundTruthWindow`` per zip spans [min ts, max ts] with those techniques.
Only ``type: atomic`` host datasets on Windows/Linux are loaded; network pcaps are skipped.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml
from lab.common.ecs import EcsEvent
from lab.common.winevent import map_windows_event
from lab.emulation.ground_truth import GroundTruthWindow
from pydantic import BaseModel

log = logging.getLogger(__name__)

RAW_BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
TREE_API = "https://api.github.com/repos/OTRF/Security-Datasets/git/trees/master?recursive=1"
METADATA_PREFIX = "datasets/atomic/_metadata/"


class OtrfMeta(BaseModel):
    id: str
    title: str
    platform: list[str]
    type: str
    description: str | None = None
    techniques: list[str]
    tactics: list[str]
    files: list[str]  # relative repo paths of host zips
    tags: list[str]


class OtrfLoader:
    dataset = "otrf"

    def __init__(self, raw_dir: Path, client: httpx.Client | None = None) -> None:
        self.raw_dir = raw_dir
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.client = client or httpx.Client(timeout=120, follow_redirects=True)

    # ------------------------------------------------------------------ download
    def _tree(self) -> list[str]:
        cache = self.raw_dir / "_tree.json"
        if cache.exists():
            data = json.loads(cache.read_text(encoding="utf-8"))
        else:
            r = self.client.get(TREE_API)
            r.raise_for_status()
            data = r.json()
            cache.write_text(json.dumps(data), encoding="utf-8")
        return [t["path"] for t in data["tree"] if t["type"] == "blob"]

    def _fetch(self, rel: str) -> Path:
        dest = self.raw_dir / rel
        if dest.exists() and dest.stat().st_size > 0:
            return dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self.client.stream("GET", RAW_BASE + rel) as r:
            r.raise_for_status()
            with dest.open("wb") as f:
                for chunk in r.iter_bytes():
                    f.write(chunk)
        return dest

    def download(self, platforms: tuple[str, ...] = ("Windows", "Linux")) -> list[OtrfMeta]:
        paths = self._tree()
        metas: list[OtrfMeta] = []
        for p in paths:
            if p.startswith(METADATA_PREFIX) and p.endswith(".yaml"):
                meta = self._parse_meta(self._fetch(p))
                if meta and any(pl in platforms for pl in meta.platform) and meta.type == "atomic":
                    for f in meta.files:
                        try:
                            self._fetch(f)
                        except httpx.HTTPError as e:  # pragma: no cover - network
                            log.warning("skip %s: %s", f, e)
                    metas.append(meta)
        return metas

    # ------------------------------------------------------------------ metadata
    def metadata(self) -> list[OtrfMeta]:
        out: list[OtrfMeta] = []
        for p in sorted((self.raw_dir / METADATA_PREFIX).glob("*.yaml")):
            m = self._parse_meta(p)
            if m:
                out.append(m)
        return out

    @staticmethod
    def _parse_meta(path: Path) -> OtrfMeta | None:
        try:
            doc: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            log.warning("bad yaml %s: %s", path, e)
            return None
        techniques: list[str] = []
        tactics: list[str] = []
        for am in doc.get("attack_mappings") or []:
            tech = str(am.get("technique", "")).strip().upper()
            sub = am.get("sub-technique")
            if tech:
                full = f"{tech}.{str(sub).zfill(3)}" if sub not in (None, "", "None") else tech
                if full not in techniques:
                    techniques.append(full)
            for ta in am.get("tactics") or []:
                if str(ta) not in tactics:
                    tactics.append(str(ta))
        files: list[str] = []
        for f in doc.get("files") or []:
            link = str(f.get("link", ""))
            # Only host telemetry zips; network pcaps are out of scope for this loader.
            if f.get("type") == "Host" and link.startswith(RAW_BASE) and link.endswith(".zip"):
                files.append(link[len(RAW_BASE) :])
        plat = doc.get("platform") or []
        return OtrfMeta(
            id=str(doc.get("id")),
            title=str(doc.get("title")),
            platform=[str(p) for p in (plat if isinstance(plat, list) else [plat])],
            type=str(doc.get("type", "atomic")),
            description=doc.get("description"),
            techniques=techniques,
            tactics=tactics,
            files=files,
            tags=[str(t).strip() for t in (doc.get("tags") or [])],
        )

    # ------------------------------------------------------------------ events
    def iter_events(self, meta: OtrfMeta) -> Iterator[EcsEvent]:
        for rel in meta.files:
            zpath = self.raw_dir / rel
            if not zpath.exists():
                log.warning("missing %s (run download)", zpath)
                continue
            yield from self._iter_zip(zpath, meta)

    def _iter_zip(self, zpath: Path, meta: OtrfMeta) -> Iterator[EcsEvent]:
        try:
            z = zipfile.ZipFile(zpath)
        except zipfile.BadZipFile:
            log.warning("bad zip %s", zpath)
            return
        tags = [f"otrf:{meta.id}", *[f"attack.{t.lower()}" for t in meta.techniques]]
        with z:
            for name in z.namelist():
                if not name.endswith(".json"):
                    continue
                with z.open(name) as fh:
                    for line in io.TextIOWrapper(fh, encoding="utf-8", errors="replace"):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            flat = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(flat, dict):
                            continue
                        ev = map_windows_event(
                            flat, dataset=self.dataset, dataset_ref=meta.id, tags=tags
                        )
                        if ev is not None:
                            if "Linux" in meta.platform and "Windows" not in meta.platform:
                                ev.host_os_type = "linux"
                            yield ev

    # ------------------------------------------------------------------ labels
    def ground_truth(
        self, meta: OtrfMeta, events: list[EcsEvent] | None = None
    ) -> list[GroundTruthWindow]:
        evs = events if events is not None else list(self.iter_events(meta))
        if not evs:
            return []
        start = min(e.timestamp for e in evs)
        end = max(e.timestamp for e in evs)
        return [
            GroundTruthWindow(
                window_id=f"otrf:{meta.id}",
                scenario_id=f"otrf:{meta.id}",
                label="tp",
                techniques=meta.techniques,
                tactics=meta.tactics,
                host=None,
                user=None,
                start_ts=start,
                end_ts=end,
                dataset=self.dataset,
                dataset_ref=meta.id,
                source="otrf_metadata",
                notes=meta.title,
            )
        ]


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
