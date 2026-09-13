"""Persistence for the review queue (SPEC §6, §9.6 audit trail).

SQLAlchemy over SQLite by default (``AEGIS_API_DSN``), so the review UI runs with no server; the
same models target Postgres in production. Stores alerts, investigations (with full state:
hypotheses, timeline, verdict, evidence ids, model + prompt versions) and analyst reviews, whose
overrides become gold labels feeding §7 training.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from aegis.db.models import Alert, Base, GoldLabel, Investigation, Review
from aegis.graph.runner import InvestigationResult

DEFAULT_DSN = os.environ.get("AEGIS_API_DSN", "sqlite:///data/aegis.db")


class Store:
    def __init__(self, dsn: str = DEFAULT_DSN) -> None:
        connect_args = {"check_same_thread": False} if dsn.startswith("sqlite") else {}
        if dsn.startswith("sqlite") and ":///" in dsn:
            from pathlib import Path

            Path(dsn.split(":///", 1)[1]).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(dsn, future=True, connect_args=connect_args)
        Base.metadata.create_all(self.engine)
        self._Session = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    def session(self) -> Session:
        return self._Session()

    # ------------------------------------------------------------------ writes
    def save_result(
        self,
        result: InvestigationResult,
        *,
        source: str = "offline",
        gold_label: str | None = None,
        dataset: str | None = None,
        fp_type: str | None = None,
    ) -> str:
        alert = result.alert
        with self.session() as s:
            if s.get(Alert, alert.alert_id) is None:
                s.add(
                    Alert(
                        id=alert.alert_id,
                        created_at=alert.time,
                        source=source,
                        rule_name=alert.finding_info.title,
                        severity=str(alert.severity or ""),
                        ocsf=alert.model_dump(mode="json"),
                        dataset=dataset,
                    )
                )
            v = result.verdict
            inv = s.get(Investigation, result.investigation_id) or Investigation(
                id=result.investigation_id, alert_id=alert.alert_id, created_at=datetime.now(tz=UTC)
            )
            inv.status = "complete"
            inv.verdict = v.label if v else None
            inv.confidence = v.confidence if v else None
            inv.severity = v.severity if v else None
            inv.techniques = v.techniques if v else []
            inv.report_md = result.report_md
            inv.playbook_id = result.playbook_id
            inv.fast_pathed = bool(v and v.fast_pathed)
            inv.injection_flagged = result.injection_flagged
            inv.tool_calls = result.spent.tool_calls
            inv.tokens = result.spent.tokens
            inv.cost_usd = result.spent.cost_usd
            inv.seconds = result.seconds
            inv.prompt_versions = result.prompt_versions
            inv.model_versions = {"reasoner": "heuristic"}
            inv.state = {
                "context": result.context.model_dump(mode="json"),
                "hypotheses": [h.model_dump(mode="json") for h in result.hypotheses],
                "timeline": [t.model_dump(mode="json") for t in result.timeline],
                "playbook": result.playbook,
                "node_log": result.node_log,
                "malicious_score": result.malicious_score,
            }
            s.merge(inv)
            if gold_label and s.get(GoldLabel, alert.alert_id) is None:
                s.add(
                    GoldLabel(
                        alert_id=alert.alert_id,
                        label=gold_label,
                        techniques=v.techniques if v else [],
                        fp_type=fp_type,
                        source="ground_truth",
                    )
                )
            s.commit()
        return result.investigation_id

    def add_review(
        self,
        investigation_id: str,
        analyst: str,
        action: str,
        override_verdict: str | None = None,
        annotation: str | None = None,
    ) -> int:
        with self.session() as s:
            inv = s.get(Investigation, investigation_id)
            if inv is None:
                raise KeyError(investigation_id)
            review = Review(
                investigation_id=investigation_id,
                reviewed_at=datetime.now(tz=UTC),
                analyst=analyst,
                action=action,
                override_verdict=override_verdict,
                annotation=annotation,
            )
            s.add(review)
            # An override becomes a training label (SPEC §5.2, §7).
            if action == "override" and override_verdict:
                gl = s.get(GoldLabel, inv.alert_id)
                if gl is None:
                    s.add(
                        GoldLabel(
                            alert_id=inv.alert_id,
                            label=override_verdict,
                            techniques=inv.techniques,
                            source="analyst_override",
                        )
                    )
                else:
                    gl.label = override_verdict
                    gl.source = "analyst_override"
            s.commit()
            return review.id

    # ------------------------------------------------------------------ reads
    def list_investigations(
        self, *, verdict: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        with self.session() as s:
            stmt = select(Investigation).order_by(Investigation.created_at.desc()).limit(limit)
            if verdict:
                stmt = stmt.where(Investigation.verdict == verdict)
            rows = s.scalars(stmt).all()
            return [self._summary(s, inv) for inv in rows]

    def get_investigation(self, investigation_id: str) -> dict[str, Any] | None:
        with self.session() as s:
            inv = s.get(Investigation, investigation_id)
            if inv is None:
                return None
            alert = s.get(Alert, inv.alert_id)
            gl = s.get(GoldLabel, inv.alert_id)
            reviews = s.scalars(
                select(Review).where(Review.investigation_id == investigation_id)
            ).all()
            return {
                **self._summary(s, inv),
                "report_md": inv.report_md,
                "state": inv.state,
                "alert": alert.ocsf if alert else None,
                "gold_label": gl.label if gl else None,
                "reviews": [
                    {
                        "analyst": r.analyst,
                        "action": r.action,
                        "override_verdict": r.override_verdict,
                        "annotation": r.annotation,
                        "reviewed_at": r.reviewed_at.isoformat(),
                    }
                    for r in reviews
                ],
            }

    def metrics(self) -> dict[str, Any]:
        with self.session() as s:
            invs = s.scalars(select(Investigation)).all()
            n = len(invs) or 1
            from collections import Counter

            by_verdict = Counter(i.verdict for i in invs if i.verdict)
            fast = sum(1 for i in invs if i.fast_pathed)
            gl = {g.alert_id: g.label for g in s.scalars(select(GoldLabel)).all()}
            correct = sum(1 for i in invs if gl.get(i.alert_id) == i.verdict and i.alert_id in gl)
            labelled = sum(1 for i in invs if i.alert_id in gl)
            return {
                "total": len(invs),
                "by_verdict": dict(by_verdict),
                "fast_path_rate": round(fast / n, 4),
                "avg_seconds": round(sum(i.seconds for i in invs) / n, 3),
                "avg_tool_calls": round(sum(i.tool_calls for i in invs) / n, 2),
                "avg_cost_usd": round(sum(i.cost_usd for i in invs) / n, 5),
                "accuracy_vs_gold": round(correct / labelled, 4) if labelled else None,
                "reviews": s.query(Review).count(),
            }

    def _summary(self, s: Session, inv: Investigation) -> dict[str, Any]:
        alert = s.get(Alert, inv.alert_id)
        return {
            "investigation_id": inv.id,
            "alert_id": inv.alert_id,
            "title": alert.rule_name if alert else "",
            "verdict": inv.verdict,
            "confidence": inv.confidence,
            "severity": inv.severity,
            "techniques": inv.techniques,
            "fast_pathed": inv.fast_pathed,
            "injection_flagged": inv.injection_flagged,
            "playbook_id": inv.playbook_id,
            "created_at": inv.created_at.isoformat(),
            "seconds": inv.seconds,
        }
