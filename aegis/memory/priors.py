"""Case-memory priors and the triage blend (Phase 1).

A *prior* is what AEGIS has learned about one key - an ATT&CK technique id or an alert source -
across past cases: how often it ended as a true positive, how often it was escalated, and how often
an analyst overrode the verdict. ``triage_pre`` blends the LightGBM ``p_tp`` with the prior's
``tp_rate`` using weight ``n / (n + K)`` so a handful of cases barely moves the model and a few
hundred dominate. Everything here is pure arithmetic over metadata; no log content is involved.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

PRIOR_K = 20  # cases needed for the prior to carry half the weight


@dataclass(frozen=True)
class Prior:
    key: str
    n: int
    tp_rate: float
    escalate_rate: float
    analyst_override_rate: float
    updated_at: str

    def to_row(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Prior:
        return cls(
            key=str(row["key"]),
            n=int(row.get("n") or 0),
            tp_rate=float(row.get("tp_rate") or 0.0),
            escalate_rate=float(row.get("escalate_rate") or 0.0),
            analyst_override_rate=float(row.get("analyst_override_rate") or 0.0),
            updated_at=str(row.get("updated_at") or ""),
        )


def prior_weight(n: int, k: int = PRIOR_K) -> float:
    n = max(0, int(n))
    return n / (n + k) if n else 0.0


def blend_p_tp(p_model: float, prior: Prior | None, k: int = PRIOR_K) -> tuple[float, float]:
    """Return ``(p_blended, weight)``. With no prior the model score passes through unchanged."""
    if prior is None or prior.n <= 0:
        return (min(1.0, max(0.0, p_model)), 0.0)
    w = prior_weight(prior.n, k)
    blended = (1.0 - w) * p_model + w * prior.tp_rate
    return (min(1.0, max(0.0, blended)), w)


def pick_prior(
    priors: dict[str, Prior], technique_ids: list[str], source: str | None
) -> Prior | None:
    """The most-evidenced technique prior for this alert, else the source prior, else None."""
    candidates = [priors[t] for t in technique_ids if t in priors]
    if candidates:
        return max(candidates, key=lambda p: p.n)
    if source and f"source:{source}" in priors:
        return priors[f"source:{source}"]
    return None


def compute_priors(
    cases: list[dict[str, Any]], feedback: list[dict[str, Any]], now: datetime | None = None
) -> dict[str, Prior]:
    """Aggregate priors from case + feedback rows (the same code runs locally and for Pulse).

    Keys are every ``attack_technique_ids`` entry and ``source:<alert_source>``.
    """
    ts = (now or datetime.now(tz=UTC)).isoformat()
    disagreed = {str(f["case_id"]) for f in feedback if f.get("agreed") is False}
    reviewed = {str(f["case_id"]) for f in feedback}
    n: dict[str, int] = defaultdict(int)
    tp: dict[str, int] = defaultdict(int)
    esc: dict[str, int] = defaultdict(int)
    rev: dict[str, int] = defaultdict(int)
    ovr: dict[str, int] = defaultdict(int)
    for c in cases:
        keys = list(c.get("attack_technique_ids") or [])
        if c.get("alert_source"):
            keys.append(f"source:{c['alert_source']}")
        cid = str(c.get("case_id"))
        for key in set(keys):
            n[key] += 1
            tp[key] += c.get("verdict") == "true_positive"
            esc[key] += bool(c.get("escalated")) or c.get("verdict") == "escalate"
            if cid in reviewed:
                rev[key] += 1
                ovr[key] += cid in disagreed
    out: dict[str, Prior] = {}
    for key, count in n.items():
        out[key] = Prior(
            key=key,
            n=count,
            tp_rate=round(tp[key] / count, 4),
            escalate_rate=round(esc[key] / count, 4),
            analyst_override_rate=round(ovr[key] / rev[key], 4) if rev[key] else 0.0,
            updated_at=ts,
        )
    return out
