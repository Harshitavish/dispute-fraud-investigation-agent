"""SQLAlchemy models.

Money is stored as integer paise everywhere. Floats and money do not mix.
"""

from __future__ import annotations

import enum
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
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class TransactionStatus(str, enum.Enum):
    CAPTURED = "captured"
    AUTHORIZED = "authorized"
    FAILED = "failed"
    REFUNDED = "refunded"


class DisputeStatus(str, enum.Enum):
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    AWAITING_HUMAN = "awaiting_human"
    RESOLVED_REFUNDED = "resolved_refunded"
    RESOLVED_REJECTED = "resolved_rejected"


class CaseStatus(str, enum.Enum):
    RUNNING = "running"
    AWAITING_HUMAN = "awaiting_human"
    COMPLETED = "completed"
    FAILED = "failed"


class Merchant(Base):
    __tablename__ = "merchants"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(80))
    # Rolling chargeback rate as a fraction (0.012 == 1.2%). Card networks put
    # merchants in monitoring programs above ~0.9%, so this is a real signal.
    chargeback_rate: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    transactions: Mapped[list["Transaction"]] = relationship(back_populates="merchant")


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(200))
    phone: Mapped[str] = mapped_column(String(32))
    # The country we have historically seen this customer transact from.
    home_country: Mapped[str] = mapped_column(String(2), default="IN")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    transactions: Mapped[list["Transaction"]] = relationship(back_populates="customer")


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    merchant_id: Mapped[str] = mapped_column(ForeignKey("merchants.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)

    amount_paise: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3), default="INR")
    status: Mapped[TransactionStatus] = mapped_column(
        Enum(TransactionStatus), default=TransactionStatus.CAPTURED
    )

    method: Mapped[str] = mapped_column(String(32))  # card / upi / netbanking
    card_bin: Mapped[str | None] = mapped_column(String(8), nullable=True)
    card_last4: Mapped[str | None] = mapped_column(String(4), nullable=True)
    card_issuer_country: Mapped[str | None] = mapped_column(String(2), nullable=True)

    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    device_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    country: Mapped[str] = mapped_column(String(2))
    city: Mapped[str] = mapped_column(String(80))

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    merchant: Mapped[Merchant] = relationship(back_populates="transactions")
    customer: Mapped[Customer] = relationship(back_populates="transactions")
    disputes: Mapped[list["Dispute"]] = relationship(back_populates="transaction")


class Dispute(Base):
    __tablename__ = "disputes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    transaction_id: Mapped[str] = mapped_column(ForeignKey("transactions.id"), index=True)

    # ISO 8583 / card-network style reason codes, simplified.
    reason_code: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text)
    amount_paise: Mapped[int] = mapped_column(Integer)
    status: Mapped[DisputeStatus] = mapped_column(
        Enum(DisputeStatus), default=DisputeStatus.OPEN, index=True
    )

    raised_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolution: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolution_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    transaction: Mapped[Transaction] = relationship(back_populates="disputes")


class IPReputation(Base):
    """Stand-in for a threat-intel feed (MaxMind / AbuseIPDB / internal SOC)."""

    __tablename__ = "ip_reputation"

    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True)
    is_tor: Mapped[bool] = mapped_column(Boolean, default=False)
    is_proxy: Mapped[bool] = mapped_column(Boolean, default=False)
    is_datacenter: Mapped[bool] = mapped_column(Boolean, default=False)
    abuse_score: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    country: Mapped[str] = mapped_column(String(2), default="IN")
    asn_org: Mapped[str] = mapped_column(String(120), default="Unknown")


class CaseRun(Base):
    """One end-to-end agent investigation over one dispute."""

    __tablename__ = "case_runs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    dispute_id: Mapped[str] = mapped_column(ForeignKey("disputes.id"), index=True)
    status: Mapped[CaseStatus] = mapped_column(Enum(CaseStatus), default=CaseStatus.RUNNING)

    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_band: Mapped[str | None] = mapped_column(String(16), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(32), nullable=True)  # agent / human
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    events: Mapped[list["AuditEvent"]] = relationship(
        back_populates="case_run", order_by="AuditEvent.sequence"
    )


class AuditEvent(Base):
    """Append-only trace of every agent step and tool call.

    In a regulated payments environment the trace is the product. If you can't
    explain why the money moved, you can't ship the automation.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_run_id: Mapped[str] = mapped_column(ForeignKey("case_runs.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)

    agent: Mapped[str] = mapped_column(String(40))
    step: Mapped[str] = mapped_column(String(80))
    tool: Mapped[str | None] = mapped_column(String(80), nullable=True)
    payload: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    case_run: Mapped[CaseRun] = relationship(back_populates="events")
