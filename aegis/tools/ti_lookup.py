"""ti_lookup tool: cached threat-intel enrichment of an observable (SPEC §4).

Classifies the observable type, checks the cache, and on a miss queries the configured provider
(the deterministic offline provider by default). Results are wrapped as ``<data>`` - a malicious TI
verdict is *evidence*, never an instruction, so injected "authorized" text in a TI field cannot
steer the agent.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from aegis.intel.cache import IntelCache
from aegis.intel.providers.base import IntelProvider, Observable
from aegis.intel.providers.offline import OfflineProvider
from aegis.tools.base import ToolResult, make_result

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.IGNORECASE)


def classify(observable: str) -> Observable:
    o = observable.strip()
    try:
        ipaddress.ip_address(o)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(o):
        return "hash"
    if o.lower().startswith(("http://", "https://")):
        return "url"
    if _DOMAIN_RE.match(o):
        return "domain"
    return "unknown"


def ti_lookup(
    observable: str,
    *,
    cache_dir: Path | None = None,
    provider: IntelProvider | None = None,
    offline: bool = True,
) -> ToolResult:
    provider = provider or OfflineProvider()
    otype = classify(observable)
    cache = IntelCache(cache_dir or (Path("data") / "intel_cache"), offline=offline)
    cached = cache.get(provider.name, observable)
    if cached is not None:
        data = {"cached": True, **cached}
    else:
        verdict = provider.lookup(observable, otype)
        data = {"cached": False, **verdict.to_dict()}
        cache.put(provider.name, observable, verdict.to_dict())
    render = (
        f"{observable} [{otype}] -> {data.get('verdict')} "
        f"(score {data.get('score')}) via {provider.name}; "
        f"categories: {', '.join(data.get('categories', [])) or 'none'}"
    )
    return make_result("ti_lookup", f"ti:{provider.name}", data, render=render, guard=True)
