"""Compact the MITRE ATT&CK STIX bundle into a small, committable technique table.

The full enterprise-attack STIX bundle is ~50 MB; AEGIS only needs id, name, tactics, platforms and
a short description per technique for mapping/validation and RAG. This produces
``aegis/attack/data/techniques.json`` (a few hundred KB) which ships with the package so the
``attack_kb`` tool and the ``attack_map`` node work offline with zero downloads.

    python -m aegis.attack.build_kb [path/to/enterprise-attack.json]

If no path is given it downloads the latest bundle from the mitre-attack/attack-stix-data repo.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import httpx

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUT = Path(__file__).parent / "data" / "techniques.json"


def _attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            eid: str | None = ref.get("external_id")
            return eid
    return None


def _url(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            url: str | None = ref.get("url")
            return url
    return None


def compact(bundle: dict[str, Any]) -> dict[str, Any]:
    objs = bundle["objects"]
    tactics: dict[str, dict[str, str]] = {}
    for o in objs:
        if o.get("type") == "x-mitre-tactic":
            tid = _attack_id(o)
            if tid:
                tactics[o["x_mitre_shortname"]] = {"id": tid, "name": o["name"]}
    techniques: dict[str, Any] = {}
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = _attack_id(o)
        if not tid:
            continue
        phases = [
            p["phase_name"]
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        desc = (o.get("description") or "").strip()
        techniques[tid] = {
            "id": tid,
            "name": o["name"],
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
            "parent": tid.split(".")[0],
            "tactics": [tactics[p]["id"] for p in phases if p in tactics],
            "tactic_names": phases,
            "platforms": o.get("x_mitre_platforms", []),
            "description": desc[:1200],
            "url": _url(o),
        }
    return {
        "version": bundle.get("id", "enterprise-attack"),
        "spec": next(
            (
                o.get("x_mitre_attack_spec_version")
                for o in objs
                if o.get("type") == "attack-pattern"
            ),
            None,
        ),
        "tactics": {v["id"]: v["name"] for v in tactics.values()},
        "techniques": techniques,
    }


def main(argv: list[str]) -> int:
    if argv:
        bundle = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    else:
        print(f"downloading {STIX_URL} ...")
        bundle = httpx.get(STIX_URL, timeout=300, follow_redirects=True).json()
    table = compact(bundle)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(table, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    print(
        f"wrote {OUT} - {len(table['techniques'])} techniques, {len(table['tactics'])} tactics, "
        f"{OUT.stat().st_size // 1024} KB"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
