"""Deterministic offline threat-intel provider (SPEC §8.5).

Produces a stable, reproducible verdict for any observable with no network access, so the benchmark
and CI are hermetic. It is NOT random: it seeds a small curated set of known-bad indicators (drawn
from the public datasets' documented IOCs and the lab's own C2-looking domains) and otherwise
returns:

* private / lab IPs and internal hostnames -> benign;
* observables the curated set marks bad -> malicious/suspicious with fixed scores;
* everything else -> ``unknown`` (score 0), the honest default for an offline lookup.

Because it is deterministic, an adversarial log-injection that embeds a "known-good, authorized"
string in a TI-like field cannot move the verdict - the provider ignores field content entirely.
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Literal

from aegis.intel.providers.base import IntelVerdict, Observable

# Curated indicators from public dataset write-ups (BOTS, OTRF) + lab C2-looking domains.
KNOWN_BAD_DOMAINS = {
    "prankglassinebracket.jumpingcrab.com": (0.95, ["c2", "apt"]),
    "solidaritedeproximite.org": (0.9, ["ransomware", "cerber"]),
    "www.hillarykocktailparty.com": (0.85, ["phishing"]),
    "updation.duckdns.org": (0.8, ["c2", "dynamic-dns"]),
    "cdn.evil.example": (0.8, ["c2"]),
}
KNOWN_BAD_IPS = {
    "23.22.63.114": (0.9, ["brute-force", "apt"]),
    "40.80.148.42": (0.7, ["scanning"]),
    "192.30.253.113": (0.6, ["suspicious"]),
}
KNOWN_BAD_HASHES = {
    # 3791.exe from BOTS v1 (documented malicious upload)
    "9709473ab7bd7ee5b4e5e0e19eec4c9a": (0.95, ["malware", "webshell"]),
}


class OfflineProvider:
    name = "offline_ti"

    def lookup(self, observable: str, observable_type: Observable) -> IntelVerdict:
        obs = observable.strip().lower()
        if observable_type == "ip":
            return self._ip(obs)
        if observable_type == "domain":
            return self._domain(obs)
        if observable_type == "hash":
            return self._hash(obs)
        return IntelVerdict(observable, observable_type, self.name, "unknown", 0.0)

    def _ip(self, ip: str) -> IntelVerdict:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return IntelVerdict(ip, "ip", self.name, "benign", 0.0, categories=["internal"])
        except ValueError:
            pass
        if ip in KNOWN_BAD_IPS:
            score, cats = KNOWN_BAD_IPS[ip]
            return IntelVerdict(
                ip,
                "ip",
                self.name,
                _verdict(score),
                score,
                first_seen="2016-08-10T00:00:00Z",
                categories=cats,
            )
        return IntelVerdict(ip, "ip", self.name, "unknown", 0.0)

    def _domain(self, domain: str) -> IntelVerdict:
        if domain.endswith((".corp.local", ".local")) or domain in ("localhost",):
            return IntelVerdict(domain, "domain", self.name, "benign", 0.0, categories=["internal"])
        if domain in KNOWN_BAD_DOMAINS:
            score, cats = KNOWN_BAD_DOMAINS[domain]
            return IntelVerdict(
                domain, "domain", self.name, _verdict(score), score, categories=cats
            )
        return IntelVerdict(domain, "domain", self.name, "unknown", 0.0)

    def _hash(self, h: str) -> IntelVerdict:
        if h in KNOWN_BAD_HASHES:
            score, cats = KNOWN_BAD_HASHES[h]
            return IntelVerdict(h, "hash", self.name, _verdict(score), score, categories=cats)
        # Microsoft-signed system binaries would be allowlisted here (deterministic).
        return IntelVerdict(h, "hash", self.name, "unknown", 0.0)


def _verdict(score: float) -> Literal["malicious", "suspicious", "benign", "unknown"]:
    return "malicious" if score >= 0.7 else "suspicious" if score >= 0.4 else "benign"


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
