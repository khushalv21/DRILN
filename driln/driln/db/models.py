"""SQLAlchemy ORM models for scan persistence.

All models use UUID primary keys and share a common ``Base`` declarative class.
Timestamps use timezone-aware UTC datetimes.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


# ── Enums ───────────────────────────────────────────────────────


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── Base ────────────────────────────────────────────────────────


class Base(DeclarativeBase):
    pass


# ── Models ──────────────────────────────────────────────────────


class Scan(Base):
    """Top-level scan record."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    target: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    tool_runs: Mapped[list[ToolRun]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    recommendations: Mapped[list[Recommendation]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )


class ToolRun(Base):
    """Record of a single tool execution within a scan."""

    __tablename__ = "tool_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    parsed_output: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="tool_runs")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="tool_run", cascade="all, delete-orphan", lazy="selectin"
    )


class Finding(Base):
    """A single vulnerability or discovery from a tool run."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tool_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity), default=Severity.INFO, nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    host: Mapped[str | None] = mapped_column(String(512), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    service: Mapped[str | None] = mapped_column(String(100), nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Intelligence fields (Phase 2)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    correlation_group: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    deduplicated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source_tools: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="findings")
    tool_run: Mapped[ToolRun | None] = relationship(back_populates="findings")


class Report(Base):
    """Generated report for a scan."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    format: Mapped[str] = mapped_column(String(20), nullable=False)  # "markdown" | "html"
    filepath: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="reports")


class Recommendation(Base):
    """AI or rule-generated next-step recommendation."""

    __tablename__ = "recommendations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    priority: Mapped[str] = mapped_column(String(20), nullable=False)  # critical/high/medium/low
    category: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # tool_suggestion | config_change | manual_check
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tool_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    source: Mapped[str] = mapped_column(
        String(30), nullable=False
    )  # "rule_engine" | "ai_analysis"
    accepted: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # None=pending
    triggered_by: Mapped[list | None] = mapped_column(JSON, nullable=True)  # finding IDs
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="recommendations")
