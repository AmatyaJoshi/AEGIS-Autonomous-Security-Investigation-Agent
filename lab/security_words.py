"""Guardrail check (SPEC §9.2): assert generated content contains no offensive payloads.

The noise generators emulate *administrative* behaviour only. This module provides a conservative
scanner used by tests and CI to assert that generated command lines never contain payload / exploit
/ shellcode markers. It is a safety net, not a substitute for review.
"""

from __future__ import annotations

import re

# Markers that should never appear in AEGIS-authored telemetry. Detection *rule* text and public
# dataset content are exempt (those are third-party, not authored here).
_OFFENSIVE = re.compile(
    r"(invoke-mimikatz|sekurlsa|lsadump|-w\s+hidden\s+-enc\s+[A-Za-z0-9+/]{200,}|"
    r"msfvenom|meterpreter|reverse[_ ]?shell|/dev/tcp/\d|bind[_ ]?shell|"
    r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}|shellcode|VirtualAllocEx.*WriteProcessMemory)",
    re.IGNORECASE,
)


def find_offensive(text: str) -> list[str]:
    return [m.group(0) for m in _OFFENSIVE.finditer(text or "")]


def assert_no_offensive_content(*texts: str) -> None:
    hits: list[str] = []
    for t in texts:
        hits.extend(find_offensive(t))
    if hits:
        raise AssertionError(f"offensive content in generated telemetry: {hits[:5]}")
