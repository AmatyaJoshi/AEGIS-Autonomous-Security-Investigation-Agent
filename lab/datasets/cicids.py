"""CIC-IDS2017 loader (network-alert track).

Source: Canadian Institute for Cybersecurity, https://www.unb.ca/cic/datasets/ids-2017.html
The CSVs (``MachineLearningCVE/*.csv`` or ``GeneratedLabelledFlows/TrafficLabelling/*.csv``) are
behind a registration form, so ``download()`` only validates a local copy (``data/raw/cicids``).

Each row is a bidirectional flow with a published ``Label`` column (``BENIGN``, ``DDoS``,
``PortScan``, ``Bot``, ``Infiltration``, ``Web Attack - Brute Force``, ``FTP-Patator`` ...). Labels
are mapped to ATT&CK below and become per-(file, label) ground-truth windows spanning the flows.
Benign flows are loaded as background traffic (no window).
"""

from __future__ import annotations

import csv
import logging
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lab.common.ecs import EcsEvent, canonical_json, make_event_id, to_int
from lab.emulation.ground_truth import GroundTruthWindow

log = logging.getLogger(__name__)

# published label -> (techniques, tactics)
LABEL_ATTACK: dict[str, tuple[list[str], list[str]]] = {
    "ddos": (["T1498.001"], ["TA0040"]),
    "dos hulk": (["T1499.002"], ["TA0040"]),
    "dos goldeneye": (["T1499.002"], ["TA0040"]),
    "dos slowloris": (["T1499.002"], ["TA0040"]),
    "dos slowhttptest": (["T1499.002"], ["TA0040"]),
    "heartbleed": (["T1190"], ["TA0001"]),
    "portscan": (["T1046"], ["TA0007"]),
    "bot": (["T1071.001"], ["TA0011"]),
    "infiltration": (["T1203", "T1071.001"], ["TA0002", "TA0011"]),
    "ftp-patator": (["T1110.001"], ["TA0006"]),
    "ssh-patator": (["T1110.001"], ["TA0006"]),
    "web attack - brute force": (["T1110.001"], ["TA0006"]),
    "web attack - xss": (["T1189", "T1190"], ["TA0001"]),
    "web attack - sql injection": (["T1190"], ["TA0001"]),
}

PROTO = {"6": "tcp", "17": "udp", "0": "hopopt", "1": "icmp"}


def normalise_label(raw: str) -> str:
    # Files use inconsistent dashes/encodings ("Web Attack \x96 XSS", "Web Attack � Brute Force")
    s = raw.strip().lower()
    for ch in (chr(0x96), chr(0xFFFD), chr(0x2013), chr(0x2014)):  # odd dashes/encodings
        s = s.replace(ch, "-")
    while "  " in s:
        s = s.replace("  ", " ")
    return s.replace(" - ", " - ").replace(" -", " -").replace("- ", "- ").replace("--", "-")


class CicIdsLoader:
    dataset = "cicids"

    def __init__(self, raw_dir: Path) -> None:
        self.raw_dir = raw_dir
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def download(self) -> list[Path]:
        files = self.files()
        if not files:
            raise FileNotFoundError(
                f"No CIC-IDS2017 CSVs under {self.raw_dir}. Register at "
                "https://www.unb.ca/cic/datasets/ids-2017.html and copy the CSV files there."
            )
        return files

    def files(self) -> list[Path]:
        return sorted(self.raw_dir.rglob("*.csv"))

    @staticmethod
    def _col(row: dict[str, Any], *names: str) -> Any:
        for n in names:
            for k, v in row.items():
                if k is not None and k.strip().lower() == n.lower():
                    return v
        return None

    def iter_events(self, path: Path) -> Iterator[EcsEvent]:
        csv.field_size_limit(sys.maxsize)
        ref = path.stem
        with path.open(encoding="utf-8", errors="replace", newline="") as f:
            for row in csv.DictReader(f):
                ts = _parse_cic_ts(self._col(row, "Timestamp"))
                if ts is None:
                    continue
                label = normalise_label(str(self._col(row, "Label") or "benign"))
                keep = {k.strip(): v for k, v in row.items() if k}
                raw = canonical_json(keep)
                proto = str(self._col(row, "Protocol") or "")
                yield EcsEvent(
                    event_id=make_event_id(self.dataset, ref, raw),
                    timestamp=ts,
                    dataset=self.dataset,
                    dataset_ref=ref,
                    event_provider="cicflowmeter",
                    event_category="network",
                    event_action="network_flow",
                    host_os_type="network",
                    source_ip=self._col(row, "Source IP", "Src IP"),
                    source_port=to_int(self._col(row, "Source Port", "Src Port")),
                    destination_ip=self._col(row, "Destination IP", "Dst IP"),
                    destination_port=to_int(self._col(row, "Destination Port", "Dst Port")),
                    network_transport=PROTO.get(proto, proto or None),
                    network_bytes=(
                        to_int(self._col(row, "Total Length of Fwd Packets", "TotLen Fwd Pkts"))
                        or 0
                    )
                    + (
                        to_int(self._col(row, "Total Length of Bwd Packets", "TotLen Bwd Pkts"))
                        or 0
                    ),
                    raw=raw,
                    tags=[f"cicids:{label}"],
                )

    def ground_truth(
        self, path: Path, events: list[EcsEvent] | None = None
    ) -> list[GroundTruthWindow]:
        evs = events if events is not None else list(self.iter_events(path))
        spans: dict[str, tuple[datetime, datetime]] = {}
        for e in evs:
            label = next((t.split(":", 1)[1] for t in e.tags if t.startswith("cicids:")), "benign")
            if label == "benign":
                continue
            lo, hi = spans.get(label, (e.timestamp, e.timestamp))
            spans[label] = (min(lo, e.timestamp), max(hi, e.timestamp))
        out: list[GroundTruthWindow] = []
        for label, (lo, hi) in sorted(spans.items()):
            techniques, tactics = LABEL_ATTACK.get(label, ([], []))
            out.append(
                GroundTruthWindow(
                    window_id=f"cicids:{path.stem}:{label}",
                    scenario_id=f"cicids:{label}",
                    label="tp",
                    techniques=techniques,
                    tactics=tactics,
                    start_ts=lo,
                    end_ts=hi,
                    dataset=self.dataset,
                    dataset_ref=path.stem,
                    source="cicids_flow_label",
                    notes=f"flow label '{label}'" + ("" if techniques else " (unmapped)"),
                )
            )
        return out


def _parse_cic_ts(v: Any) -> datetime | None:
    """CIC timestamps are local (ADT, UTC-3), e.g. ``5/7/2017 8:55`` or ``05/07/2017 08:55:01 AM``.

    Naive values are shifted +3h to UTC.
    """
    if not v:
        return None
    from datetime import timedelta

    from dateutil import parser as dtp

    try:
        dt = dtp.parse(str(v), dayfirst=True)
    except (ValueError, OverflowError):
        return None
    if dt.tzinfo is None:
        dt = dt + timedelta(hours=3)  # ADT -> UTC
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)
