"""Side-effecting tools: refunds, rejections, fraud escalation.

These are the only functions in the system that move money or change a
dispute's terminal state. They are deliberately small, explicit, and
idempotent -- an agent that retries a step must not double-refund a customer.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Dispute, DisputeStatus, Transaction, TransactionStatus


def _idempotency_key(dispute_id: str, action: str) -> str:
    return "idem_" + hashlib.sha256(f"{dispute_id}:{action}".encode()).hexdigest()[:24]


def issue_refund(session: Session, dispute_id: str, reason: str, actor: str) -> dict[str, Any]:
    """Simulates POST /v1/payments/:id/refund against the payment gateway.

    Idempotent: calling it twice on an already-refunded dispute returns the
    existing outcome instead of moving money again.
    """
    dispute = session.get(Dispute, dispute_id)
    if dispute is None:
        return {"ok": False, "error": "dispute_not_found", "dispute_id": dispute_id}

    key = _idempotency_key(dispute_id, "refund")

    if dispute.status == DisputeStatus.RESOLVED_REFUNDED:
        return {
            "ok": True,
            "idempotent_replay": True,
            "refund_id": f"rfnd_{key[5:17]}",
            "dispute_id": dispute_id,
            "amount_paise": dispute.amount_paise,
            "status": "processed",
        }

    txn = session.get(Transaction, dispute.transaction_id)
    txn.status = TransactionStatus.REFUNDED

    dispute.status = DisputeStatus.RESOLVED_REFUNDED
    dispute.resolution = "refund"
    dispute.resolution_reason = reason
    dispute.resolved_at = datetime.now(timezone.utc)
    session.flush()

    return {
        "ok": True,
        "idempotent_replay": False,
        "refund_id": f"rfnd_{key[5:17]}",
        "idempotency_key": key,
        "dispute_id": dispute_id,
        "transaction_id": txn.id,
        "amount_paise": dispute.amount_paise,
        "currency": txn.currency,
        "speed": "normal",
        "status": "processed",
        "decided_by": actor,
    }


def reject_dispute(session: Session, dispute_id: str, reason: str, actor: str) -> dict[str, Any]:
    """Close a dispute against the claimant (represent / defend the charge)."""
    dispute = session.get(Dispute, dispute_id)
    if dispute is None:
        return {"ok": False, "error": "dispute_not_found", "dispute_id": dispute_id}

    if dispute.status == DisputeStatus.RESOLVED_REJECTED:
        return {"ok": True, "idempotent_replay": True, "dispute_id": dispute_id, "status": "rejected"}

    dispute.status = DisputeStatus.RESOLVED_REJECTED
    dispute.resolution = "reject"
    dispute.resolution_reason = reason
    dispute.resolved_at = datetime.now(timezone.utc)
    session.flush()

    return {
        "ok": True,
        "idempotent_replay": False,
        "dispute_id": dispute_id,
        "status": "rejected",
        "reason": reason,
        "decided_by": actor,
    }


def mark_awaiting_human(session: Session, dispute_id: str, reason: str) -> dict[str, Any]:
    dispute = session.get(Dispute, dispute_id)
    if dispute is None:
        return {"ok": False, "error": "dispute_not_found", "dispute_id": dispute_id}
    dispute.status = DisputeStatus.AWAITING_HUMAN
    dispute.resolution_reason = reason
    session.flush()
    return {"ok": True, "dispute_id": dispute_id, "status": "awaiting_human", "reason": reason}


def raise_fraud_alert(
    session: Session, *, dispute_id: str, transaction_id: str, signals: list[str], score: float
) -> dict[str, Any]:
    """Hand the case to fraud ops / SOC.

    In production this would publish to a queue and open a case in the fraud
    console. Here it produces the alert payload that would be published.
    """
    txn = session.get(Transaction, transaction_id)
    severity = "critical" if score >= 85 else "high"
    return {
        "ok": True,
        "alert_id": f"alrt_{_idempotency_key(dispute_id, 'alert')[5:17]}",
        "severity": severity,
        "dispute_id": dispute_id,
        "transaction_id": transaction_id,
        "customer_id": txn.customer_id if txn else None,
        "merchant_id": txn.merchant_id if txn else None,
        "indicators": signals,
        "risk_score": score,
        "recommended_actions": [
            "Freeze the payment instrument pending customer contact",
            "Force re-authentication on the customer account",
            "Sweep for sibling transactions sharing the device fingerprint or IP",
        ],
    }
