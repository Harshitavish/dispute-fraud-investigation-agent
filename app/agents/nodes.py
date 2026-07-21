"""The agent nodes.

Four specialists, each with a narrow remit and its own tool surface:

  fetcher        -> read-only data tools (SQL)
  threat_analyst -> scoring engine + LLM adjudication (no write access at all)
  policy         -> pure function, no I/O, no model
  executors      -> the only nodes permitted to move money
  communicator   -> SMTP tool only

Separating them this way is not decoration. The analyst cannot issue a refund
even if it decides it wants to, because it holds no refund tool. Capability is
enforced by what each node can reach, not by asking a model to behave.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from app.agents.llm import LLMClient
from app.agents.policy import band_for, decide
from app.agents.state import CaseState
from app.db.models import AuditEvent, CaseRun, CaseStatus
from app.db.session import session_scope
from app.tools import action_tools, email_tools, sql_tools, threat_tools

_llm = LLMClient()


# --------------------------------------------------------------------------
# audit helper
# --------------------------------------------------------------------------


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def _record(
    case_run_id: str,
    agent: str,
    step: str,
    payload: dict[str, Any],
    *,
    tool: str | None = None,
    latency_ms: int = 0,
) -> dict[str, Any]:
    """Persist one audit row and return the in-memory trace entry."""
    entry = {
        "agent": agent,
        "step": step,
        "tool": tool,
        "payload": _json_safe(payload),
        "latency_ms": latency_ms,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with session_scope() as session:
            seq = (
                session.query(AuditEvent).filter(AuditEvent.case_run_id == case_run_id).count() + 1
            )
            session.add(
                AuditEvent(
                    case_run_id=case_run_id,
                    sequence=seq,
                    agent=agent,
                    step=step,
                    tool=tool,
                    payload=json.dumps(entry["payload"], default=str)[:60_000],
                    latency_ms=latency_ms,
                )
            )
        entry["sequence"] = seq
    except Exception as exc:  # noqa: BLE001 - audit must never break the run
        entry["audit_persist_error"] = f"{type(exc).__name__}: {exc}"
    return entry


# --------------------------------------------------------------------------
# 1. Fetcher agent
# --------------------------------------------------------------------------


def fetcher_node(state: CaseState) -> dict[str, Any]:
    """Gathers every piece of context the investigation needs, in one pass.

    Six tool calls, all read-only. Doing this up front rather than letting a
    downstream agent fetch lazily keeps the evidence set fixed for the whole
    case -- which is what makes a decision reproducible from the audit log.
    """
    started = time.perf_counter()
    dispute_id = state["dispute_id"]
    run_id = state["case_run_id"]
    trace: list[dict[str, Any]] = []

    with session_scope() as session:
        base = sql_tools.fetch_dispute(session, dispute_id)
        if base is None:
            entry = _record(run_id, "fetcher", "dispute_not_found", {"dispute_id": dispute_id})
            return {"fetch_error": f"Dispute {dispute_id} not found", "trace": [entry]}

        trace.append(
            _record(
                run_id,
                "fetcher",
                "loaded_dispute",
                {
                    "dispute_id": dispute_id,
                    "amount": base["dispute"]["amount_display"],
                    "reason_code": base["dispute"]["reason_code"],
                },
                tool="fetch_dispute",
            )
        )

        customer_id = base["customer"]["id"]
        ip = base["transaction"]["ip_address"]

        profile = sql_tools.fetch_customer_profile(
            session, customer_id, as_of_iso=base["transaction"]["created_at"]
        )
        trace.append(
            _record(
                run_id,
                "fetcher",
                "built_customer_baseline",
                {
                    "transactions": profile["total_transactions"],
                    "avg_amount": profile["avg_amount_display"],
                    "prior_disputes": profile["prior_disputes"],
                },
                tool="fetch_customer_profile",
            )
        )

        velocity = sql_tools.fetch_velocity(
            session, customer_id, base["transaction"]["created_at"]
        )
        trace.append(
            _record(
                run_id,
                "fetcher",
                "measured_velocity",
                velocity,
                tool="fetch_velocity",
            )
        )

        recent = sql_tools.fetch_recent_transactions(session, customer_id, limit=8)
        trace.append(
            _record(
                run_id, "fetcher", "pulled_timeline", {"count": len(recent)},
                tool="fetch_recent_transactions",
            )
        )

        reputation = sql_tools.fetch_ip_reputation(session, ip)
        trace.append(
            _record(
                run_id,
                "fetcher",
                "queried_threat_feed",
                {
                    "ip": ip,
                    "abuse_score": reputation["abuse_score"],
                    "asn_org": reputation["asn_org"],
                },
                tool="fetch_ip_reputation",
            )
        )

        cluster = sql_tools.fetch_ip_shared_accounts(session, ip)
        trace.append(
            _record(
                run_id, "fetcher", "checked_ip_cluster", cluster, tool="fetch_ip_shared_accounts"
            )
        )

    context = {
        **base,
        "profile": profile,
        "velocity": velocity,
        "recent_transactions": recent,
        "ip_reputation": reputation,
        "ip_cluster": cluster,
    }

    elapsed = int((time.perf_counter() - started) * 1000)
    trace.append(
        _record(
            run_id, "fetcher", "context_assembled", {"tool_calls": 6}, latency_ms=elapsed
        )
    )
    return {"context": context, "fetch_error": None, "trace": trace}


# --------------------------------------------------------------------------
# 2. Threat Analyst agent
# --------------------------------------------------------------------------


def threat_analyst_node(state: CaseState) -> dict[str, Any]:
    """Scores the evidence, then asks the model to interpret it."""
    started = time.perf_counter()
    run_id = state["case_run_id"]
    ctx = state["context"]
    trace: list[dict[str, Any]] = []

    signals = threat_tools.evaluate_signals(
        transaction=ctx["transaction"],
        customer=ctx["customer"],
        profile=ctx["profile"],
        velocity=ctx["velocity"],
        ip_reputation=ctx["ip_reputation"],
        ip_cluster=ctx["ip_cluster"],
        merchant=ctx["merchant"],
        dispute=ctx["dispute"],
    )
    risk_score = threat_tools.score(signals)
    risk_band = band_for(risk_score)
    serialised = threat_tools.serialise(signals)

    trace.append(
        _record(
            run_id,
            "threat_analyst",
            "scored_signals",
            {
                "risk_score": risk_score,
                "risk_band": risk_band,
                "triggered": threat_tools.triggered_names(signals),
            },
            tool="evaluate_signals",
        )
    )

    from app.agents.policy import rules_action_for

    provisional = rules_action_for(risk_band)

    llm_started = time.perf_counter()
    adjudication = _llm.adjudicate(
        context=ctx,
        signals=serialised,
        risk_score=risk_score,
        risk_band=risk_band,
        policy_action=provisional,
    )
    llm_ms = int((time.perf_counter() - llm_started) * 1000)

    trace.append(
        _record(
            run_id,
            "threat_analyst",
            "adjudicated",
            {
                "source": adjudication.get("source"),
                "typology": adjudication.get("fraud_typology"),
                "recommended_action": adjudication.get("recommended_action"),
                "confidence": adjudication.get("confidence"),
                "assessment": adjudication.get("assessment"),
                "dissent": adjudication.get("dissent"),
            },
            tool="claude.adjudicate",
            latency_ms=llm_ms,
        )
    )

    with session_scope() as session:
        run = session.get(CaseRun, run_id)
        if run:
            run.risk_score = risk_score
            run.risk_band = risk_band
            run.summary = adjudication.get("assessment")

    _ = int((time.perf_counter() - started) * 1000)
    return {
        "signals": serialised,
        "risk_score": risk_score,
        "risk_band": risk_band,
        "adjudication": adjudication,
        "trace": trace,
    }


# --------------------------------------------------------------------------
# 3. Policy engine
# --------------------------------------------------------------------------


def policy_node(state: CaseState) -> dict[str, Any]:
    run_id = state["case_run_id"]
    ctx = state["context"]

    action, rules_action, reasons = decide(
        risk_score=state["risk_score"],
        amount_paise=ctx["dispute"]["amount_paise"],
        llm_recommendation=state["adjudication"].get("recommended_action"),
    )

    entry = _record(
        run_id,
        "policy",
        "decided",
        {"decision": action, "rules_action": rules_action, "reasons": reasons},
    )

    with session_scope() as session:
        run = session.get(CaseRun, run_id)
        if run:
            run.decision = action
            run.decided_by = "agent"

    return {
        "decision": action,
        "rules_action": rules_action,
        "decision_reasons": reasons,
        "decided_by": "agent",
        "trace": [entry],
    }


def route_after_policy(state: CaseState) -> str:
    return {
        "auto_refund": "execute_refund",
        "reject_and_flag": "execute_rejection",
        "manual_review": "queue_for_human",
    }[state["decision"]]


# --------------------------------------------------------------------------
# 4a. Human-in-the-loop
# --------------------------------------------------------------------------


def queue_for_human_node(state: CaseState) -> dict[str, Any]:
    """Park the case and tell the customer it is being looked at.

    Runs *before* the interrupt so the customer is not left in silence while
    the case waits in a queue.
    """
    run_id = state["case_run_id"]
    ctx = state["context"]
    trace: list[dict[str, Any]] = []

    with session_scope() as session:
        result = action_tools.mark_awaiting_human(
            session, ctx["dispute"]["id"], "; ".join(state["decision_reasons"])
        )
        run = session.get(CaseRun, run_id)
        if run:
            run.status = CaseStatus.AWAITING_HUMAN

    trace.append(_record(run_id, "action", "queued_for_human", result, tool="mark_awaiting_human"))

    draft = _llm.draft_notification(
        audience="customer",
        decision="manual_review",
        context=ctx,
        assessment=state["adjudication"].get("assessment", ""),
    )
    sent = email_tools.send_email(
        to=ctx["customer"]["email"],
        subject=draft["subject"],
        body=draft["body"],
        tag="review",
    )
    trace.append(
        _record(
            run_id,
            "communicator",
            "notified_customer_pending",
            {"draft_source": draft.get("source"), **sent},
            tool="send_email",
        )
    )

    return {
        "notifications": [{"audience": "customer", "stage": "pending", **draft, **sent}],
        "trace": trace,
    }


def human_review_node(state: CaseState) -> dict[str, Any]:
    """Executed only after a human resumes the graph with a decision."""
    run_id = state["case_run_id"]
    human = state.get("human_decision")
    notes = state.get("human_notes") or ""

    decision = "auto_refund" if human == "approve_refund" else "reject_and_flag"
    entry = _record(
        run_id,
        "human",
        "reviewed",
        {"human_decision": human, "notes": notes, "resulting_action": decision},
    )

    with session_scope() as session:
        run = session.get(CaseRun, run_id)
        if run:
            run.status = CaseStatus.RUNNING
            run.decision = decision
            run.decided_by = "human"

    return {
        "decision": decision,
        "decided_by": "human",
        "decision_reasons": [*state.get("decision_reasons", []), f"Human reviewer: {human}. {notes}".strip()],
        "trace": [entry],
    }


def route_after_human(state: CaseState) -> str:
    return "execute_refund" if state["decision"] == "auto_refund" else "execute_rejection"


# --------------------------------------------------------------------------
# 4b. Executors -- the only nodes that touch money
# --------------------------------------------------------------------------


def execute_refund_node(state: CaseState) -> dict[str, Any]:
    run_id = state["case_run_id"]
    ctx = state["context"]
    reason = "; ".join(state.get("decision_reasons", []))[:2000]

    with session_scope() as session:
        result = action_tools.issue_refund(
            session, ctx["dispute"]["id"], reason, state.get("decided_by", "agent")
        )

    entry = _record(run_id, "action", "issued_refund", result, tool="issue_refund")
    return {"action_result": result, "fraud_alert": None, "trace": [entry]}


def execute_rejection_node(state: CaseState) -> dict[str, Any]:
    run_id = state["case_run_id"]
    ctx = state["context"]
    reason = "; ".join(state.get("decision_reasons", []))[:2000]
    trace: list[dict[str, Any]] = []

    with session_scope() as session:
        result = action_tools.reject_dispute(
            session, ctx["dispute"]["id"], reason, state.get("decided_by", "agent")
        )
        trace.append(_record(run_id, "action", "rejected_dispute", result, tool="reject_dispute"))

        alert = None
        # A rejection driven by fraud indicators needs a SOC ticket. A
        # rejection a human made on the merits does not.
        if state.get("risk_band") == "HIGH":
            triggered = [s["name"] for s in state.get("signals", []) if s["triggered"]]
            alert = action_tools.raise_fraud_alert(
                session,
                dispute_id=ctx["dispute"]["id"],
                transaction_id=ctx["transaction"]["id"],
                signals=triggered,
                score=state["risk_score"],
            )
            trace.append(
                _record(run_id, "action", "raised_fraud_alert", alert, tool="raise_fraud_alert")
            )

    return {"action_result": result, "fraud_alert": alert, "trace": trace}


# --------------------------------------------------------------------------
# 5. Communicator agent
# --------------------------------------------------------------------------


def communicator_node(state: CaseState) -> dict[str, Any]:
    """Writes and dispatches the closing notifications."""
    run_id = state["case_run_id"]
    ctx = state["context"]
    decision = state["decision"]
    assessment = state["adjudication"].get("assessment", "")
    trace: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []

    # Customer
    draft = _llm.draft_notification(
        audience="customer", decision=decision, context=ctx, assessment=assessment
    )
    sent = email_tools.send_email(
        to=ctx["customer"]["email"], subject=draft["subject"], body=draft["body"], tag=decision
    )
    notifications.append({"audience": "customer", "stage": "final", **draft, **sent})
    trace.append(
        _record(
            run_id,
            "communicator",
            "notified_customer",
            {"decision": decision, "draft_source": draft.get("source"), **sent},
            tool="send_email",
        )
    )

    # Merchant -- only when the outcome actually affects them.
    if decision in ("auto_refund", "reject_and_flag"):
        m_draft = _llm.draft_notification(
            audience="merchant", decision=decision, context=ctx, assessment=assessment
        )
        m_sent = email_tools.send_email(
            to=ctx["merchant"]["email"],
            subject=m_draft["subject"],
            body=m_draft["body"],
            tag=f"merchant_{decision}",
        )
        notifications.append({"audience": "merchant", "stage": "final", **m_draft, **m_sent})
        trace.append(
            _record(
                run_id,
                "communicator",
                "notified_merchant",
                {"decision": decision, "draft_source": m_draft.get("source"), **m_sent},
                tool="send_email",
            )
        )

    with session_scope() as session:
        run = session.get(CaseRun, run_id)
        if run:
            run.status = CaseStatus.COMPLETED
            run.finished_at = datetime.now(timezone.utc)

    trace.append(_record(run_id, "orchestrator", "case_closed", {"decision": decision}))
    return {"notifications": notifications, "trace": trace}
