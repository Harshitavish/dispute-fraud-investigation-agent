"""Data-retrieval tools. These are what the Fetcher agent is allowed to call.

Every tool takes an explicit Session and returns a plain JSON-safe dict, so the
agent layer never touches ORM objects and the audit log can serialise anything
a tool returns.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import (
    Customer,
    Dispute,
    DisputeStatus,
    IPReputation,
    Merchant,
    Transaction,
    utcnow,
)


def _rupees(paise: int) -> str:
    return f"Rs. {paise / 100:,.2f}"


def fetch_dispute(session: Session, dispute_id: str) -> dict[str, Any] | None:
    """Load a dispute with its transaction, merchant and customer context."""
    dispute = session.get(Dispute, dispute_id)
    if dispute is None:
        return None

    txn = session.get(Transaction, dispute.transaction_id)
    merchant = session.get(Merchant, txn.merchant_id)
    customer = session.get(Customer, txn.customer_id)

    return {
        "dispute": {
            "id": dispute.id,
            "reason_code": dispute.reason_code,
            "description": dispute.description,
            "amount_paise": dispute.amount_paise,
            "amount_display": _rupees(dispute.amount_paise),
            "status": dispute.status.value,
            "raised_at": dispute.raised_at.isoformat(),
            "hours_since_transaction": round(
                (dispute.raised_at - txn.created_at).total_seconds() / 3600, 1
            ),
        },
        "transaction": {
            "id": txn.id,
            "amount_paise": txn.amount_paise,
            "amount_display": _rupees(txn.amount_paise),
            "status": txn.status.value,
            "method": txn.method,
            "card_bin": txn.card_bin,
            "card_last4": txn.card_last4,
            "card_issuer_country": txn.card_issuer_country,
            "ip_address": txn.ip_address,
            "device_fingerprint": txn.device_fingerprint,
            "country": txn.country,
            "city": txn.city,
            "created_at": txn.created_at.isoformat(),
        },
        "merchant": {
            "id": merchant.id,
            "name": merchant.name,
            "email": merchant.email,
            "category": merchant.category,
            "chargeback_rate": merchant.chargeback_rate,
        },
        "customer": {
            "id": customer.id,
            "name": customer.name,
            "email": customer.email,
            "phone": customer.phone,
            "home_country": customer.home_country,
            "account_age_days": (utcnow() - customer.created_at.replace(tzinfo=utcnow().tzinfo)).days
            if customer.created_at.tzinfo is None
            else (utcnow() - customer.created_at).days,
        },
    }


def fetch_customer_profile(
    session: Session,
    customer_id: str,
    as_of_iso: str | None = None,
    quarantine_hours: int = 24,
) -> dict[str, Any]:
    """Aggregate behavioural baselines for a customer.

    This is what separates 'a suspicious-looking transaction' from 'a
    transaction that is suspicious *for this customer*'.

    Critically, the baseline is built only from activity that predates the
    disputed charge by at least `quarantine_hours`. Without that cutoff an
    attacker's own burst of transactions gets counted as the victim's normal
    behaviour -- the takeover establishes the country and device as "known",
    and the geo/device signals it should have tripped go quiet. The fraud
    launders its own baseline. Anything inside the quarantine window is
    evidence, never precedent.
    """
    cutoff = None
    if as_of_iso:
        from datetime import datetime

        cutoff = (
            datetime.fromisoformat(as_of_iso) - timedelta(hours=quarantine_hours)
        ).replace(tzinfo=None)

    def _baseline(stmt):
        stmt = stmt.where(Transaction.customer_id == customer_id)
        if cutoff is not None:
            stmt = stmt.where(Transaction.created_at < cutoff)
        return stmt

    stats = session.execute(
        _baseline(
            select(
                func.count(Transaction.id),
                func.avg(Transaction.amount_paise),
                func.max(Transaction.amount_paise),
                func.sum(Transaction.amount_paise),
            )
        )
    ).one()

    total_txns = stats[0] or 0
    avg_amount = float(stats[1] or 0)
    max_amount = int(stats[2] or 0)
    lifetime_value = int(stats[3] or 0)

    known_devices = session.scalars(
        _baseline(select(Transaction.device_fingerprint)).distinct()
    ).all()

    known_countries = session.scalars(_baseline(select(Transaction.country)).distinct()).all()

    prior_disputes = session.execute(
        _baseline(
            select(func.count(Dispute.id)).join(
                Transaction, Dispute.transaction_id == Transaction.id
            )
        )
    ).scalar_one()

    refunded_disputes = session.execute(
        _baseline(
            select(func.count(Dispute.id))
            .join(Transaction, Dispute.transaction_id == Transaction.id)
            .where(Dispute.status == DisputeStatus.RESOLVED_REFUNDED)
        )
    ).scalar_one()

    return {
        "customer_id": customer_id,
        "baseline_cutoff": cutoff.isoformat() if cutoff else None,
        "total_transactions": total_txns,
        "avg_amount_paise": round(avg_amount, 2),
        "avg_amount_display": _rupees(int(avg_amount)),
        "max_amount_paise": max_amount,
        "lifetime_value_paise": lifetime_value,
        "known_devices": list(known_devices),
        "known_countries": list(known_countries),
        "prior_disputes": prior_disputes,
        "prior_refunded_disputes": refunded_disputes,
        "dispute_rate": round(prior_disputes / total_txns, 4) if total_txns else 0.0,
    }


def fetch_velocity(session: Session, customer_id: str, as_of_iso: str | None = None) -> dict[str, Any]:
    """Transaction counts and volumes in the windows before the disputed charge."""
    as_of = utcnow()
    if as_of_iso:
        from datetime import datetime

        as_of = datetime.fromisoformat(as_of_iso)

    def _window(hours: int) -> dict[str, Any]:
        since = as_of - timedelta(hours=hours)
        rows = session.execute(
            select(func.count(Transaction.id), func.sum(Transaction.amount_paise)).where(
                Transaction.customer_id == customer_id,
                Transaction.created_at >= since.replace(tzinfo=None),
                Transaction.created_at <= as_of.replace(tzinfo=None),
            )
        ).one()
        return {"count": rows[0] or 0, "amount_paise": int(rows[1] or 0)}

    return {
        "customer_id": customer_id,
        "last_1h": _window(1),
        "last_24h": _window(24),
        "last_7d": _window(24 * 7),
    }


def fetch_recent_transactions(
    session: Session, customer_id: str, limit: int = 10
) -> list[dict[str, Any]]:
    """The most recent transactions, newest first -- the investigator's timeline."""
    txns = session.scalars(
        select(Transaction)
        .where(Transaction.customer_id == customer_id)
        .order_by(Transaction.created_at.desc())
        .limit(limit)
    ).all()

    return [
        {
            "id": t.id,
            "amount_display": _rupees(t.amount_paise),
            "amount_paise": t.amount_paise,
            "status": t.status.value,
            "ip_address": t.ip_address,
            "device_fingerprint": t.device_fingerprint,
            "country": t.country,
            "city": t.city,
            "created_at": t.created_at.isoformat(),
        }
        for t in txns
    ]


def fetch_ip_reputation(session: Session, ip_address: str) -> dict[str, Any]:
    """Threat-intel lookup. Unknown IPs are treated as neutral, not as safe."""
    rep = session.get(IPReputation, ip_address)
    if rep is None:
        return {
            "ip_address": ip_address,
            "known": False,
            "is_tor": False,
            "is_proxy": False,
            "is_datacenter": False,
            "abuse_score": 25,  # unknown != clean
            "country": "??",
            "asn_org": "Unknown",
        }
    return {
        "ip_address": rep.ip_address,
        "known": True,
        "is_tor": rep.is_tor,
        "is_proxy": rep.is_proxy,
        "is_datacenter": rep.is_datacenter,
        "abuse_score": rep.abuse_score,
        "country": rep.country,
        "asn_org": rep.asn_org,
    }


def fetch_ip_shared_accounts(session: Session, ip_address: str) -> dict[str, Any]:
    """How many distinct customers transacted from this IP -- a farming signal."""
    customers = session.scalars(
        select(Transaction.customer_id).where(Transaction.ip_address == ip_address).distinct()
    ).all()
    return {"ip_address": ip_address, "distinct_customers": len(customers), "customer_ids": list(customers)}


def list_open_disputes(session: Session) -> list[dict[str, Any]]:
    disputes = session.scalars(
        select(Dispute)
        .where(Dispute.status.in_([DisputeStatus.OPEN, DisputeStatus.AWAITING_HUMAN]))
        .order_by(Dispute.raised_at.desc())
    ).all()
    return [
        {
            "id": d.id,
            "transaction_id": d.transaction_id,
            "reason_code": d.reason_code,
            "amount_display": _rupees(d.amount_paise),
            "status": d.status.value,
            "raised_at": d.raised_at.isoformat(),
        }
        for d in disputes
    ]
