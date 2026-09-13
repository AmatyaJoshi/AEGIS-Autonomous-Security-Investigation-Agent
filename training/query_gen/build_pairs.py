"""Build the NL->SIEM-query training corpus (SPEC §7.2, "the clever part").

Three aligned sources:

1. **Sigma-derived pairs** - every rule in the curated pack already has a title+description (the NL
   side) and machine conversions to ES|QL and SPL (the query side). One pair per (rule, dialect).
2. **LLM/paraphrase augmentation** - 3 template paraphrases of each rule's NL side (offline,
   deterministic; with an API key these would be model paraphrases) to teach intent variation.
3. **Investigative-intent templates** - parametric intents ("show all process creations by {user}
   on {host} in the last {window}", "logons for {user} outside business hours") instantiated on the
   lab's real entities, paired with the programmatically-generated DuckDB query from the
   TemplateQueryBuilder. These are execution-checkable offline (they run against the snapshot).

Entire Sigma **categories** (default: ``proxy``) are held out as a test split to measure
generalisation. Output: ``pairs.jsonl`` (+ datacard). Target 15-25k pairs.

    python -m training.query_gen.build_pairs
"""

from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aegis.models.query_gen import Entity, QuerySpec, TemplateQueryBuilder, detect_aspect
from aegis.siem.base import TimeWindow
from lab.rules.convert import read_pack

OUT = Path("training") / "query_gen" / "data"
HOLDOUT_CATEGORIES = {"proxy", "webserver"}


@dataclass
class Pair:
    nl: str
    query: str
    dialect: str
    source: str  # sigma | paraphrase | intent
    category: str
    split: str  # train | test
    entities: list[str] = field(default_factory=list)
    window_days: int | None = None


def _paraphrase(title: str, desc: str | None) -> list[str]:
    d = (desc or "").strip().rstrip(".")
    base = title.strip()
    out = [
        f"Find activity where {base[0].lower() + base[1:]}",
        f"Detect {base.lower()}",
    ]
    if d:
        out.append(f"Show events matching: {d}")
    return out[:3]


def sigma_pairs(pack_dir: Path) -> list[Pair]:
    pairs: list[Pair] = []
    for rec in read_pack(pack_dir):
        cat = rec.logsource.get("category") or rec.logsource.get("service") or "other"
        split = "test" if (rec.holdout or cat in HOLDOUT_CATEGORIES) else "train"
        nl_variants = [f"{rec.title}." + (f" {rec.description}" if rec.description else "")]
        nl_variants += _paraphrase(rec.title, rec.description)
        for i, nl in enumerate(nl_variants):
            src = "sigma" if i == 0 else "paraphrase"
            if rec.esql:
                pairs.append(
                    Pair(
                        nl=nl.strip(),
                        query=rec.esql,
                        dialect="esql",
                        source=src,
                        category=cat,
                        split=split,
                    )
                )
            if rec.spl:
                pairs.append(
                    Pair(
                        nl=nl.strip(),
                        query=rec.spl,
                        dialect="spl",
                        source=src,
                        category=cat,
                        split=split,
                    )
                )
    return pairs


# Investigative-intent templates instantiated on lab entities.
_INTENT_TEMPLATES = [
    ("show all process creations by {user} on {host} in the last {win}", "process"),
    ("find network connections from {host} to external hosts", "network"),
    ("list logons for {user} outside business hours", "logon"),
    ("show powershell script block activity on {host}", "powershell"),
    ("find file writes by {user} on {host}", "file"),
    ("show registry modifications on {host}", "registry"),
    ("list dns queries from {host}", "dns"),
    ("find the parent process chain for activity by {user} on {host}", "parent"),
    ("show services installed on {host}", "service"),
    ("find processes with the same hash across {host}", "hash"),
    ("show failed logons for {user} on {host}", "logon"),
    ("list all activity by {user} on {host} in the last {win}", "process"),
]
_HOSTS = ["DC01", "WS-DEV1", "WS-ALICE", "FS01", "SQL01", "BACKUP01", "SCCM01", "WEB01"]
_USERS = ["adm.patel", "dev.kumar", "svc_backup", "alice.ng", "hd.singh", "svc_sccm", "bob.reyes"]
_WINDOWS = [("1 hour", 1 / 24), ("24 hours", 1), ("7 days", 7), ("14 days", 14)]


def intent_pairs(n: int, seed: int = 7) -> list[Pair]:
    rng = random.Random(seed)
    builder = TemplateQueryBuilder()
    base = datetime(2025, 1, 6, 12, tzinfo=UTC)
    pairs: list[Pair] = []
    for _ in range(n):
        tmpl, _aspect = rng.choice(_INTENT_TEMPLATES)
        host = rng.choice(_HOSTS)
        user = rng.choice(_USERS)
        win_label, win_days = rng.choice(_WINDOWS)
        nl = tmpl.format(user=user, host=host, win=win_label)
        entities = [
            e
            for e in (host, user)
            if "{" + ("host" if e == host else "user") + "}" in tmpl or e in nl
        ]
        entities = list(
            dict.fromkeys([host if "{host}" in tmpl else None, user if "{user}" in tmpl else None])
        )
        entities = [e for e in entities if e]
        window = TimeWindow(start=base - timedelta(days=win_days), end=base)
        spec = QuerySpec(
            intent=nl,
            entities=[Entity.classify(e, set(_HOSTS)) for e in entities],
            window=window,
            aspect=detect_aspect(nl),
        )
        for dialect in ("duckdb", "esql"):
            q = builder.build(spec, dialect=dialect)  # type: ignore[arg-type]
            pairs.append(
                Pair(
                    nl=nl,
                    query=q,
                    dialect=dialect,
                    source="intent",
                    category="intent",
                    split="test" if rng.random() < 0.15 else "train",
                    entities=entities,
                    window_days=int(win_days) or 1,
                )
            )
    return pairs


def build(pack_dir: Path, out_dir: Path = OUT, n_intent: int = 6000) -> dict[str, Any]:
    pairs = sigma_pairs(pack_dir) + intent_pairs(n_intent)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "pairs.jsonl").write_text(
        "\n".join(json.dumps(asdict(p)) for p in pairs), encoding="utf-8"
    )
    card = {
        "n_pairs": len(pairs),
        "by_source": dict(Counter(p.source for p in pairs)),
        "by_dialect": dict(Counter(p.dialect for p in pairs)),
        "by_split": dict(Counter(p.split for p in pairs)),
        "holdout_categories": sorted(HOLDOUT_CATEGORIES),
        "test_categories": sorted({p.category for p in pairs if p.split == "test"}),
    }
    (out_dir / "datacard.json").write_text(json.dumps(card, indent=1), encoding="utf-8")
    return card


def load_pairs(out_dir: Path = OUT) -> list[Pair]:
    path = out_dir / "pairs.jsonl"
    return [
        Pair(**json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line
    ]


if __name__ == "__main__":
    import argparse

    from aegis.config import get_settings

    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", default=None)
    ap.add_argument("--n-intent", type=int, default=6000)
    args = ap.parse_args()
    pack = Path(args.pack) if args.pack else get_settings().data.rules
    print(json.dumps(build(pack, n_intent=args.n_intent), indent=1))
