"""Splunk Boss of the SOC (BOTS) loader.

BOTS v1-v3 are distributed as Splunk app tarballs (tens of GB) and cannot be pulled anonymously from
a stable URL, so this loader consumes an **export** you produce from Splunk yourself:

    | search index=botsv1 sourcetype IN ("XmlWinEventLog:*", "WinEventLog:*", "stream:http",
        "stream:dns", "suricata", "fgt_traffic") | table _time host source sourcetype _raw

exported as JSON (``| outputjson`` or the UI "Export -> JSON") or CSV. Point ``download()`` at that
file (or set ``AEGIS_BOTS_EXPORT``). Rows are mapped by sourcetype:

* ``XmlWinEventLog:*`` - ``_raw`` is Windows event XML -> parsed to a flat dict -> Windows mapper
* ``WinEventLog:*``    - classic ``Key=Value`` text -> flat dict -> Windows mapper
* ``stream:http`` / ``stream:dns`` / ``suricata`` / ``fgt_traffic`` - JSON ``_raw`` -> network event

Ground truth comes from ``lab/datasets/bots_windows.yaml``: attack windows transcribed from the
*published* BOTS answer material (scenario write-ups and the official question/answer sets). Each
window carries a ``ref`` to its source and ``reviewed: false`` until an analyst confirms it in the
UI. Nothing is inferred by AEGIS itself.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from lab.common.ecs import EcsEvent, canonical_json, make_event_id, parse_ts, to_int
from lab.common.winevent import map_windows_event
from lab.emulation.ground_truth import GroundTruthWindow

log = logging.getLogger(__name__)

WINDOWS_YAML = Path(__file__).with_name("bots_windows.yaml")
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class BotsLoader:
    dataset = "bots"

    def __init__(self, raw_dir: Path, export: Path | None = None) -> None:
        self.raw_dir = raw_dir
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        env = os.environ.get("AEGIS_BOTS_EXPORT")
        self.export = export or (Path(env) if env else None)

    # ------------------------------------------------------------------ download
    def download(self) -> list[Path]:
        """BOTS cannot be fetched automatically; verify the user-supplied export exists."""
        candidates = (
            [self.export]
            if self.export
            else sorted(self.raw_dir.glob("*.json*")) + sorted(self.raw_dir.glob("*.csv"))
        )
        found = [p for p in candidates if p and p.exists()]
        if not found:
            raise FileNotFoundError(
                "No BOTS export found. Export from Splunk (see lab/datasets/bots.py docstring) "
                f"and place it under {self.raw_dir} or set AEGIS_BOTS_EXPORT."
            )
        return found

    # ------------------------------------------------------------------ rows
    def _rows(self, path: Path) -> Iterator[dict[str, Any]]:
        if path.suffix.lower() == ".csv":
            csv.field_size_limit(sys.maxsize)
            with path.open(encoding="utf-8", errors="replace", newline="") as f:
                yield from csv.DictReader(f)
            return
        with path.open(encoding="utf-8", errors="replace") as f:
            head = f.read(1)
            f.seek(0)
            if head == "[":
                data = json.load(f)
                yield from (r for r in data if isinstance(r, dict))
            else:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            r = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(r, dict):
                            yield r.get("result", r)

    # ------------------------------------------------------------------ events
    def iter_events(self, path: Path, version: str = "botsv1") -> Iterator[EcsEvent]:
        ref = version
        for row in self._rows(path):
            st = str(row.get("sourcetype", ""))
            raw = row.get("_raw")
            if not isinstance(raw, str):
                continue
            ts = parse_ts(row.get("_time"))
            ev: EcsEvent | None
            if st.startswith("XmlWinEventLog"):
                flat = parse_win_xml(raw)
                if flat is None:
                    continue
                flat.setdefault("Hostname", row.get("host"))
                ev = map_windows_event(
                    flat, dataset=self.dataset, dataset_ref=ref, tags=[f"bots:{st}"], default_ts=ts
                )
            elif st.startswith("WinEventLog"):
                flat = parse_win_kv(raw)
                flat.setdefault("Hostname", row.get("host"))
                ev = map_windows_event(
                    flat, dataset=self.dataset, dataset_ref=ref, tags=[f"bots:{st}"], default_ts=ts
                )
            else:
                ev = self._network_event(row, st, raw, ref, ts)
            if ev is not None:
                yield ev

    def _network_event(
        self, row: dict[str, Any], st: str, raw: str, ref: str, ts: datetime | None
    ) -> EcsEvent | None:
        try:
            body: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            body = {"_raw": raw}
        ts = ts or parse_ts(body.get("timestamp"), body.get("date"))
        if ts is None:
            return None
        canon = canonical_json({"sourcetype": st, "host": row.get("host"), **body})
        src = body.get("src_ip") or body.get("src") or body.get("srcip")
        dst = body.get("dest_ip") or body.get("dest") or body.get("dstip")
        return EcsEvent(
            event_id=make_event_id(self.dataset, ref, canon),
            timestamp=ts,
            dataset=self.dataset,
            dataset_ref=ref,
            event_provider=st,
            event_category="network",
            event_action=st.split(":")[-1],
            host_name=str(row.get("host")).upper() if row.get("host") else None,
            host_os_type="network",
            source_ip=str(src) if src else None,
            source_port=to_int(body.get("src_port") or body.get("srcport")),
            destination_ip=str(dst) if dst else None,
            destination_port=to_int(body.get("dest_port") or body.get("dstport")),
            network_transport=str(body.get("transport") or body.get("proto") or "").lower() or None,
            network_bytes=to_int(body.get("bytes")),
            url_original=body.get("url") or body.get("uri_path"),
            http_user_agent=body.get("http_user_agent"),
            dns_question_name=(body.get("query") or [None])[0]
            if isinstance(body.get("query"), list)
            else body.get("query"),
            raw=canon,
            tags=[f"bots:{st}"],
        )

    # ------------------------------------------------------------------ labels
    def ground_truth(self, version: str = "botsv1") -> list[GroundTruthWindow]:
        doc = yaml.safe_load(WINDOWS_YAML.read_text(encoding="utf-8"))
        out: list[GroundTruthWindow] = []
        for w in doc.get(version, []):
            out.append(
                GroundTruthWindow(
                    window_id=f"bots:{version}:{w['id']}",
                    scenario_id=f"bots:{version}:{w['scenario']}",
                    step=int(w.get("step", 0)),
                    label=w.get("label", "tp"),
                    techniques=w.get("techniques", []),
                    tactics=w.get("tactics", []),
                    host=w.get("host"),
                    user=w.get("user"),
                    start_ts=_dt(w["start"]),
                    end_ts=_dt(w["end"]),
                    dataset=self.dataset,
                    dataset_ref=version,
                    source="bots_answers",
                    notes=f"{w.get('notes', '')} [ref: {w.get('ref', '')}]".strip(),
                    reviewed=bool(w.get("reviewed", False)),
                )
            )
        return out


def _dt(v: Any) -> datetime:
    d = parse_ts(v)
    if d is None:
        raise ValueError(f"bad timestamp {v!r}")
    return d.astimezone(UTC)


def parse_win_xml(raw: str) -> dict[str, Any] | None:
    """Windows event XML (``<Event xmlns=...>``) -> flat OTRF-style dict."""
    try:
        root = ET.fromstring(raw.strip())
    except ET.ParseError:
        return None
    flat: dict[str, Any] = {}
    system = root.find("e:System", _NS)
    if system is None:
        return None
    prov = system.find("e:Provider", _NS)
    if prov is not None:
        flat["SourceName"] = prov.get("Name")
    for tag in ("EventID", "Channel", "Computer", "EventRecordID", "Task", "Level"):
        el = system.find(f"e:{tag}", _NS)
        if el is not None and el.text:
            flat[tag if tag != "Computer" else "Hostname"] = el.text
    if "EventID" in flat:
        flat["EventID"] = to_int(flat["EventID"])
    tc = system.find("e:TimeCreated", _NS)
    if tc is not None:
        flat["TimeCreated"] = tc.get("SystemTime")
    for data in root.iterfind(".//e:EventData/e:Data", _NS):
        name = data.get("Name")
        if name:
            flat[name] = data.text
    return flat


_KV_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _\-]*?)\s*[=:]\s*(.*)$")


def parse_win_kv(raw: str) -> dict[str, Any]:
    """Classic Splunk ``WinEventLog`` text (``EventCode=4688`` ...) -> flat dict."""
    flat: dict[str, Any] = {}
    for line in raw.splitlines():
        m = _KV_RE.match(line)
        if not m:
            continue
        k, v = m.group(1).strip(), m.group(2).strip()
        key = {
            "EventCode": "EventID",
            "ComputerName": "Hostname",
            "LogName": "Channel",
            "New Process Name": "NewProcessName",
            "Process Command Line": "CommandLine",
            "Creator Process Name": "ParentProcessName",
            "Account Name": "SubjectUserName",
            "Account Domain": "SubjectDomainName",
            "Logon Type": "LogonType",
            "Source Network Address": "IpAddress",
        }.get(k, k.replace(" ", ""))
        flat.setdefault(key, v)
    if "EventID" in flat:
        flat["EventID"] = to_int(flat["EventID"])
    return flat
