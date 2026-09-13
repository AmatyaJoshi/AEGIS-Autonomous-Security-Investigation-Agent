"""EVTX-ATTACK-SAMPLES loader.

Source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES - ~280 ``.evtx`` files organised by
tactic folder (``Credential Access/``, ``Lateral Movement/``...) with technique ids in file names
(e.g. ``LM_sysmon_3_1_wmiprvse_psexec_t1077.evtx``, ``4794_DSRM_password_change_t1098.evtx``).

Parsing uses the Rust-backed ``evtx`` package (``PyEvtxParser.records_json``). Labels come from the
published folder + filename only; files without a parseable ``T####`` tag are still loaded (they are
attack telemetry) but get technique ``[]`` and are flagged ``notes="technique not tagged in name"``
so the benchmark builder can exclude or review them.
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from collections.abc import Iterator
from pathlib import Path

import httpx
from lab.common.ecs import EcsEvent
from lab.common.winevent import flatten_evtx, map_windows_event
from lab.emulation.ground_truth import TACTIC_IDS, GroundTruthWindow

log = logging.getLogger(__name__)

ARCHIVE_URL = "https://codeload.github.com/sbousseaden/EVTX-ATTACK-SAMPLES/zip/refs/heads/master"
TECH_RE = re.compile(r"[tT](\d{4})(?:[._](\d{3}))?")

FOLDER_TACTIC: dict[str, str] = {
    "credential access": "credential-access",
    "defense evasion": "defense-evasion",
    "discovery": "discovery",
    "execution": "execution",
    "lateral movement": "lateral-movement",
    "persistence": "persistence",
    "privilege escalation": "privilege-escalation",
    "command and control": "command-and-control",
    "collection": "collection",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "initial access": "initial-access",
}


class EvtxAttackLoader:
    dataset = "evtx_attack"

    def __init__(self, raw_dir: Path, client: httpx.Client | None = None) -> None:
        self.raw_dir = raw_dir
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.client = client or httpx.Client(timeout=300, follow_redirects=True)

    # ------------------------------------------------------------------ download
    def download(self) -> Path:
        archive = self.raw_dir / "EVTX-ATTACK-SAMPLES-master.zip"
        if not archive.exists():
            with self.client.stream("GET", ARCHIVE_URL) as r:
                r.raise_for_status()
                with archive.open("wb") as f:
                    for chunk in r.iter_bytes():
                        f.write(chunk)
        self.extract(archive)
        return archive

    def extract(self, archive: Path) -> int:
        n = 0
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if not info.filename.lower().endswith(".evtx"):
                    continue
                rel = Path(*Path(info.filename).parts[1:])  # strip repo-root folder
                dest = self.raw_dir / "samples" / rel
                if dest.exists():
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(z.read(info))
                n += 1
        return n

    # ------------------------------------------------------------------ files
    def files(self) -> list[Path]:
        return sorted((self.raw_dir / "samples").rglob("*.evtx"))

    @staticmethod
    def sample_ref(path: Path, root: Path) -> str:
        rel = path.relative_to(root).as_posix()
        return rel[:-5] if rel.lower().endswith(".evtx") else rel

    @staticmethod
    def parse_labels(path: Path) -> tuple[list[str], list[str]]:
        techniques: list[str] = []
        for m in TECH_RE.finditer(path.stem):
            t = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
            if t not in techniques:
                techniques.append(t)
        tactics: list[str] = []
        for part in path.parts[:-1]:
            name = FOLDER_TACTIC.get(part.lower())
            if name and TACTIC_IDS[name] not in tactics:
                tactics.append(TACTIC_IDS[name])
        return techniques, tactics

    # ------------------------------------------------------------------ events
    def iter_events(self, path: Path) -> Iterator[EcsEvent]:
        import evtx

        root = self.raw_dir / "samples"
        ref = self.sample_ref(path, root) if path.is_relative_to(root) else path.stem
        techniques, _ = self.parse_labels(
            path.relative_to(root) if path.is_relative_to(root) else path
        )
        tags = [f"evtx:{path.stem}", *[f"attack.{t.lower()}" for t in techniques]]
        try:
            parser = evtx.PyEvtxParser(str(path))
        except Exception as e:
            log.warning("cannot open %s: %s", path, e)
            return
        for rec in parser.records_json():
            try:
                record = json.loads(rec["data"])
            except (KeyError, json.JSONDecodeError):
                continue
            flat = flatten_evtx(record)
            flat.setdefault("EventRecordID", rec.get("event_record_id"))
            ev = map_windows_event(flat, dataset=self.dataset, dataset_ref=ref, tags=tags)
            if ev is not None:
                yield ev

    # ------------------------------------------------------------------ labels
    def ground_truth(
        self, path: Path, events: list[EcsEvent] | None = None
    ) -> list[GroundTruthWindow]:
        root = self.raw_dir / "samples"
        rel = path.relative_to(root) if path.is_relative_to(root) else Path(path.name)
        ref = self.sample_ref(path, root) if path.is_relative_to(root) else path.stem
        evs = events if events is not None else list(self.iter_events(path))
        if not evs:
            return []
        techniques, tactics = self.parse_labels(rel)
        return [
            GroundTruthWindow(
                window_id=f"evtx:{ref}",
                scenario_id=f"evtx:{ref}",
                label="tp",
                techniques=techniques,
                tactics=tactics,
                start_ts=min(e.timestamp for e in evs),
                end_ts=max(e.timestamp for e in evs),
                dataset=self.dataset,
                dataset_ref=ref,
                source="evtx_filename",
                notes=None if techniques else "technique not tagged in name",
            )
        ]
