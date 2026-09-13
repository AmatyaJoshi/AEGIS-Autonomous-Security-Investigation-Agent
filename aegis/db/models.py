"""SQLAlchemy models for the review queue and audit trail (SPEC §2.1, §9.6).

Phase 1 defines the schema; the FastAPI service and LangGraph checkpointer write to it in later
phases. Tables mirror the artefacts an investigation produces so the full audit trail (hypotheses,
queries, evidence ids, model + prompt versions) is queryable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # OCSF finding uid
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(32))  # elastic | splunk | sigma
    rule_name: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    ocsf: Mapped[dict[str, Any]] = mapped_column(JSON)
    dataset: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dataset_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)

    investigations: Mapped[list[Investigation]] = relationship(back_populates="alert")
    label: Mapped[GoldLabel | None] = relationship(back_populates="alert", uselist=False)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="running")
    verdict: Mapped[str | None] = mapped_column(String(24), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    report_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    playbook_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fast_pathed: Mapped[bool] = mapped_column(default=False)
    injection_flagged: Mapped[bool] = mapped_column(default=False)
    tool_calls: Mapped[int] = mapped_column(Integer, default=0)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    seconds: Mapped[float] = mapped_column(Float, default=0.0)
    prompt_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    model_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    state: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )  # hypotheses, timeline, evidence

    alert: Mapped[Alert] = relationship(back_populates="investigations")
    review: Mapped[Review | None] = relationship(back_populates="investigation", uselist=False)


class Review(Base):
    __tablename__ = "reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    analyst: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(16))  # approve | override | annotate
    override_verdict: Mapped[str | None] = mapped_column(String(24), nullable=True)
    annotation: Mapped[str | None] = mapped_column(Text, nullable=True)

    investigation: Mapped[Investigation] = relationship(back_populates="review")


class GoldLabel(Base):
    """Benchmark / ground-truth label for an alert (feeds §7 training and §8 scoring)."""

    __tablename__ = "gold_labels"

    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    label: Mapped[str] = mapped_column(String(24))  # true_positive | false_positive | escalate
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    fp_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(32))  # ground_truth | analyst_override | co_labeller
    split: Mapped[str | None] = mapped_column(String(8), nullable=True)  # train | val | test
    scenario_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    alert: Mapped[Alert] = relationship(back_populates="label")


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    yaml: Mapped[str] = mapped_column(Text)
