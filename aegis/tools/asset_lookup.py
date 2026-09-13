"""asset_lookup / identity_lookup tools backed by the lab mock CMDB / IdP (``lab/noise/org.yaml``).

These give the investigation the asset criticality and identity privilege that drive verdict
severity and playbook selection. In a real deployment the same interface is backed by a CMDB and an
IdP; the lab uses the deterministic org model so investigations are reproducible.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from aegis.tools.base import ToolResult, make_result

ORG_YAML = Path(__file__).resolve().parent.parent.parent / "lab" / "noise" / "org.yaml"


@lru_cache(maxsize=4)
def _org(path: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(Path(path or ORG_YAML).read_text(encoding="utf-8"))
    return data


def _norm_host(name: str) -> str:
    return name.strip().upper().split(".")[0]


def asset_lookup(host: str, org_path: str | None = None) -> ToolResult:
    org = _org(org_path)
    key = _norm_host(host)
    match = next((h for h in org["hosts"] if _norm_host(h["name"]) == key), None)
    if match is None:
        data = {
            "host": host,
            "known": False,
            "criticality": "unknown",
            "note": "host not in CMDB; treat as unmanaged",
        }
    else:
        owner = next((u for u in org["users"] if u["name"] == match.get("owner")), None)
        data = {
            "host": match["name"],
            "known": True,
            "os": match.get("os"),
            "role": match.get("role"),
            "criticality": match.get("criticality"),
            "zone": match.get("zone"),
            "ip": match.get("ip"),
            "owner": match.get("owner"),
            "owner_privileged": bool(owner and owner.get("privileged")),
        }
    render = "\n".join(f"{k}: {v}" for k, v in data.items())
    return make_result("asset_lookup", f"cmdb:{host}", data, render=render, guard=False)


def identity_lookup(user: str, org_path: str | None = None) -> ToolResult:
    org = _org(org_path)
    key = user.strip().lower().split("\\")[-1]
    match = next((u for u in org["users"] if u["name"].lower() == key), None)
    if match is None:
        data = {
            "user": user,
            "known": False,
            "privileged": False,
            "note": "user not in IdP; could be local/service account or attacker-created",
        }
    else:
        data = {
            "user": match["name"],
            "known": True,
            "role": match.get("role"),
            "department": match.get("dept"),
            "privileged": bool(match.get("privileged")),
            "local_admin": bool(match.get("local_admin")),
            "service_account": match.get("service") is not None,
            "service": match.get("service"),
            "groups": match.get("groups", []),
            "notes": match.get("notes"),
        }
    render = "\n".join(f"{k}: {v}" for k, v in data.items())
    return make_result("identity_lookup", f"idp:{user}", data, render=render, guard=False)
