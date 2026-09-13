"""Render the benchmark report.html (SPEC §8, definition-of-done)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

TEMPLATE = Path(__file__).parent / "report_template.html"


def render_report(
    scores: dict[str, Any], meta: dict[str, Any], out_path: Path, roc_dir: Path | None = None
) -> Path:
    rocs: dict[str, Any] = {}
    if roc_dir:
        for arm in scores:
            rp = roc_dir / f"roc_{arm}.json"
            if rp.exists():
                rocs[arm] = json.loads(rp.read_text(encoding="utf-8"))
    html = TEMPLATE.read_text(encoding="utf-8")
    html = html.replace(
        "/*__DATA__*/",
        f"const SCORES = {json.dumps(scores)};\n"
        f"const META = {json.dumps(meta)};\n"
        f"const ROCS = {json.dumps(rocs)};",
    )
    out_path.write_text(html, encoding="utf-8")
    return out_path
