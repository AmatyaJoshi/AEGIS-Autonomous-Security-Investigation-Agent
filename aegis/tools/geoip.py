"""geoip tool (SPEC §4). Uses MaxMind GeoLite2 when a DB is configured; otherwise offline logic.

Offline behaviour (no DB present): private/reserved ranges resolve to the lab's own location and are
flagged ``is_internal``; public IPs return ``country: unknown`` rather than a fabricated location -
an honest "no data" beats an invented geolocation that could mislead a verdict.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any

from aegis.tools.base import ToolResult, error_result, make_result


def geoip(ip: str, *, db_path: str | None = None) -> ToolResult:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return error_result("geoip", f"geoip:{ip}", f"not an IP address: {ip!r}")

    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        data: dict[str, Any] = {
            "ip": ip,
            "is_internal": True,
            "country": None,
            "note": "private/reserved range - internal asset",
        }
        return make_result(
            "geoip", f"geoip:{ip}", data, render=f"{ip}: internal (private/reserved)", guard=False
        )

    db = db_path or os.environ.get("AEGIS_GEOIP_DB")
    if db and Path(db).exists():
        data = _maxmind(ip, db)
    else:
        data = {
            "ip": ip,
            "is_internal": False,
            "country": None,
            "note": "no GeoLite2 DB configured; geolocation unavailable offline",
        }
    render = f"{ip}: {data.get('country') or 'unknown'} {data.get('city') or ''}".strip()
    return make_result("geoip", f"geoip:{ip}", data, render=render, guard=False)


def _maxmind(ip: str, db: str) -> dict[str, Any]:
    try:
        import geoip2.database
    except ImportError:
        return {"ip": ip, "is_internal": False, "country": None, "note": "geoip2 not installed"}
    with geoip2.database.Reader(db) as reader:
        resp = reader.city(ip)
        return {
            "ip": ip,
            "is_internal": False,
            "country": resp.country.iso_code,
            "country_name": resp.country.name,
            "city": resp.city.name,
            "latitude": resp.location.latitude,
            "longitude": resp.location.longitude,
        }
