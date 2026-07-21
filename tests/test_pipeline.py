"""End-to-end tests over the four seeded scenarios.

These run the real graph against the real (SQLite) database with the LLM in
its deterministic fallback mode, so they are hermetic and require no API key.
"""

from __future__ import annotations

import pytest

from app.agents.graph import resume_investigation, start_investigation
from app.db.models import Dispute, DisputeStatus, Transaction, TransactionStatus
from app.db.seed import seed
from app.db.session import session_scope
from app.tools import action_tools, sql_tools


@pytest.fixture(autouse=True)
def fresh_db():
    """Every test starts from the same known dataset."""
    seed(reset=True)
    yield


# --------------------------------------------------------------------------
# scenario coverage
# --------------------------------------------------------------------------


def test_clean_low_risk_dispute_is_auto_refunded() -> None:
    result = start_investigation("dsp_001")

    assert result["risk_band"] == "LOW"
    assert result["decision"] == "auto_refund"
    assert result["status"] == "completed"
    assert result["action_result"]["ok"] is True
    assert result["fraud_alert"] is None

    with session_scope() as session:
        dispute = session.get(Dispute, "dsp_001")
        txn = session.get(Transaction, "txn_clean_001")
        assert dispute.status == DisputeStatus.RESOLVED_REFUNDED
        assert txn.status == TransactionStatus.REFUNDED


def test_account_takeover_is_rejected_and_escalated_to_fraud_ops() -> None:
    result = start_investigation("dsp_002")

    assert result["risk_band"] == "HIGH"
    assert result["decision"] == "reject_and_flag"

    triggered = set(result["triggered_signals"])
    # The signature of a takeover: anonymised origin, unfamiliar geography,
    # unfamiliar device, and a charge far outside the victim's norm.
    assert {"anonymised_network", "geo_mismatch", "unrecognised_device", "amount_anomaly"} <= triggered

    assert result["fraud_alert"] is not None
    assert result["fraud_alert"]["severity"] == "critical"

    with session_scope() as session:
        assert session.get(Dispute, "dsp_002").status == DisputeStatus.RESOLVED_REJECTED


def test_friendly_fraud_pattern_is_escalated_to_a_human() -> None:
    result = start_investigation("dsp_003")

    assert result["risk_band"] == "MEDIUM"
    assert result["decision"] == "manual_review"
    assert result["status"] == "awaiting_human"
    assert "serial_refund_claimant" in result["triggered_signals"]

    # Nothing was paid out while the case sits in the queue.
    with session_scope() as session:
        assert session.get(Dispute, "dsp_003").status == DisputeStatus.AWAITING_HUMAN


def test_high_value_dispute_bypasses_auto_refund() -> None:
    """Low risk score, large amount -> a human still has to look at it."""
    result = start_investigation("dsp_004")

    assert result["risk_band"] == "LOW"
    assert result["decision"] == "manual_review"
    assert result["status"] == "awaiting_human"
    assert any("High-value guardrail" in r for r in result["decision_reasons"])


# --------------------------------------------------------------------------
# human-in-the-loop
# --------------------------------------------------------------------------


def test_paused_case_resumes_and_completes_on_human_approval() -> None:
    first = start_investigation("dsp_003")
    assert first["status"] == "awaiting_human"

    resumed = resume_investigation(
        first["case_run_id"], human_decision="approve_refund", notes="Evidence checked."
    )

    assert resumed["status"] == "completed"
    assert resumed["decision"] == "auto_refund"
    assert resumed["decided_by"] == "human"
    assert resumed["action_result"]["ok"] is True

    with session_scope() as session:
        assert session.get(Dispute, "dsp_003").status == DisputeStatus.RESOLVED_REFUNDED


def test_human_rejection_closes_the_case_without_paying_out() -> None:
    first = start_investigation("dsp_004")
    resumed = resume_investigation(
        first["case_run_id"], human_decision="reject", notes="Airline confirmed one charge."
    )

    assert resumed["decision"] == "reject_and_flag"
    # Rejected on the merits by a human, not on fraud indicators -- so no SOC ticket.
    assert resumed["fraud_alert"] is None

    with session_scope() as session:
        assert session.get(Dispute, "dsp_004").status == DisputeStatus.RESOLVED_REJECTED


def test_resuming_a_finished_case_is_rejected() -> None:
    done = start_investigation("dsp_001")
    with pytest.raises(ValueError, match="not paused"):
        resume_investigation(done["case_run_id"], human_decision="approve_refund")


# --------------------------------------------------------------------------
# tool-level invariants
# --------------------------------------------------------------------------


def test_refund_is_idempotent() -> None:
    """A retried step must not pay the customer twice."""
    with session_scope() as session:
        first = action_tools.issue_refund(session, "dsp_001", "test", "agent")
        second = action_tools.issue_refund(session, "dsp_001", "test", "agent")

    assert first["idempotent_replay"] is False
    assert second["idempotent_replay"] is True
    assert first["refund_id"] == second["refund_id"]


def test_baseline_quarantines_contemporaneous_activity() -> None:
    """The attacker's own burst must not become the victim's 'normal'."""
    with session_scope() as session:
        txn = session.get(Transaction, "txn_ato_002")

        polluted = sql_tools.fetch_customer_profile(session, "cst_rohan", as_of_iso=None)
        quarantined = sql_tools.fetch_customer_profile(
            session, "cst_rohan", as_of_iso=txn.created_at.isoformat()
        )

    # Without the cutoff the fraudulent country/device look established.
    assert "RU" in polluted["known_countries"]
    assert "dev_unknown_headless" in polluted["known_devices"]

    # With it, they are correctly unfamiliar.
    assert "RU" not in quarantined["known_countries"]
    assert "dev_unknown_headless" not in quarantined["known_devices"]


def test_unknown_dispute_id_fails_closed() -> None:
    result = start_investigation("dsp_does_not_exist")
    assert result["error"] is not None
    assert result["decision"] is None
    assert result["action_result"] is None


def test_every_case_produces_an_audit_trail() -> None:
    result = start_investigation("dsp_001")
    steps = {(e["agent"], e["step"]) for e in result["trace"]}

    assert ("fetcher", "loaded_dispute") in steps
    assert ("threat_analyst", "scored_signals") in steps
    assert ("policy", "decided") in steps
    assert ("action", "issued_refund") in steps
    assert ("communicator", "notified_customer") in steps
    # Sequence numbers are contiguous and ordered.
    seqs = [e["sequence"] for e in result["trace"] if "sequence" in e]
    assert seqs == sorted(seqs) == list(range(1, len(seqs) + 1))
