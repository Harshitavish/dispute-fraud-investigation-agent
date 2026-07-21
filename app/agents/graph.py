"""LangGraph wiring, plus the run/resume API the service layer calls.

Why LangGraph rather than a chain of function calls:

  * Conditional edges make the routing explicit and inspectable, instead of
    burying it in if/else inside a driver loop.
  * The checkpointer persists state at every super-step, so a case that stops
    for human review can be resumed later from exactly where it paused.
  * `interrupt_before` gives real human-in-the-loop rather than a simulated
    pause -- the graph genuinely halts mid-execution.
"""

from __future__ import annotations

import uuid
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from app.agents.nodes import (
    communicator_node,
    execute_refund_node,
    execute_rejection_node,
    fetcher_node,
    human_review_node,
    policy_node,
    queue_for_human_node,
    route_after_human,
    route_after_policy,
    threat_analyst_node,
)
from app.agents.state import CaseState
from app.db.models import CaseRun, CaseStatus
from app.db.session import session_scope

_checkpointer = MemorySaver()


def build_graph():
    graph = StateGraph(CaseState)

    graph.add_node("fetcher", fetcher_node)
    graph.add_node("threat_analyst", threat_analyst_node)
    graph.add_node("policy", policy_node)
    graph.add_node("queue_for_human", queue_for_human_node)
    graph.add_node("human_review", human_review_node)
    graph.add_node("execute_refund", execute_refund_node)
    graph.add_node("execute_rejection", execute_rejection_node)
    graph.add_node("communicator", communicator_node)

    graph.add_edge(START, "fetcher")

    # Bail out early if the dispute does not exist -- no point scoring nothing.
    graph.add_conditional_edges(
        "fetcher",
        lambda s: "abort" if s.get("fetch_error") else "continue",
        {"abort": END, "continue": "threat_analyst"},
    )

    graph.add_edge("threat_analyst", "policy")

    graph.add_conditional_edges(
        "policy",
        route_after_policy,
        {
            "execute_refund": "execute_refund",
            "execute_rejection": "execute_rejection",
            "queue_for_human": "queue_for_human",
        },
    )

    # Execution pauses here. Nothing past this edge runs until a human resumes.
    graph.add_edge("queue_for_human", "human_review")
    graph.add_conditional_edges(
        "human_review",
        route_after_human,
        {"execute_refund": "execute_refund", "execute_rejection": "execute_rejection"},
    )

    graph.add_edge("execute_refund", "communicator")
    graph.add_edge("execute_rejection", "communicator")
    graph.add_edge("communicator", END)

    return graph.compile(checkpointer=_checkpointer, interrupt_before=["human_review"])


COMPILED = build_graph()


def _config(case_run_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": case_run_id}}


def start_investigation(dispute_id: str) -> dict[str, Any]:
    """Run the graph until it finishes or pauses for a human."""
    case_run_id = f"run_{uuid.uuid4().hex[:16]}"

    with session_scope() as session:
        session.add(CaseRun(id=case_run_id, dispute_id=dispute_id, status=CaseStatus.RUNNING))

    initial: CaseState = {
        "case_run_id": case_run_id,
        "dispute_id": dispute_id,
        "trace": [],
        "notifications": [],
        "human_decision": None,
        "human_notes": None,
    }

    try:
        final = COMPILED.invoke(initial, _config(case_run_id))
    except Exception as exc:  # noqa: BLE001 - surface failures as case state
        with session_scope() as session:
            run = session.get(CaseRun, case_run_id)
            if run:
                run.status = CaseStatus.FAILED
                run.summary = f"{type(exc).__name__}: {exc}"
        raise

    return _summarise(case_run_id, final)


def resume_investigation(case_run_id: str, human_decision: str, notes: str = "") -> dict[str, Any]:
    """Feed a human decision back in and let the graph run to completion."""
    config = _config(case_run_id)
    snapshot = COMPILED.get_state(config)

    if not snapshot.next:
        raise ValueError(f"Case {case_run_id} is not paused; nothing to resume.")

    COMPILED.update_state(config, {"human_decision": human_decision, "human_notes": notes})
    final = COMPILED.invoke(None, config)
    return _summarise(case_run_id, final)


def pending_node(case_run_id: str) -> str | None:
    """Which node the graph is parked in front of, if any."""
    snapshot = COMPILED.get_state(_config(case_run_id))
    return snapshot.next[0] if snapshot.next else None


def _plain_overview(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """The human-readable facts of the case, for non-technical readers."""
    if not ctx:
        return None
    return {
        "customer_name": ctx["customer"]["name"],
        "merchant_name": ctx["merchant"]["name"],
        "amount_display": ctx["dispute"]["amount_display"],
        "paid_on": ctx["transaction"]["created_at"][:10],
        "paid_from": f"{ctx['transaction']['city']}, {ctx['transaction']['country']}",
        "payment_method": ctx["transaction"]["method"],
        "complaint": ctx["dispute"]["description"],
        "reason": ctx["dispute"]["reason_code"].replace("_", " ").lower(),
    }


def _summarise(case_run_id: str, final: dict[str, Any]) -> dict[str, Any]:
    awaiting = pending_node(case_run_id) == "human_review"
    return {
        "case_run_id": case_run_id,
        "dispute_id": final.get("dispute_id"),
        "overview": _plain_overview(final.get("context") or {}),
        "status": "awaiting_human" if awaiting else "completed",
        "error": final.get("fetch_error"),
        "risk_score": final.get("risk_score"),
        "risk_band": final.get("risk_band"),
        "decision": final.get("decision"),
        "decided_by": final.get("decided_by"),
        "decision_reasons": final.get("decision_reasons", []),
        "adjudication": final.get("adjudication"),
        "triggered_signals": [s["name"] for s in final.get("signals", []) if s["triggered"]],
        "signals": final.get("signals", []),
        "action_result": final.get("action_result"),
        "fraud_alert": final.get("fraud_alert"),
        "notifications": final.get("notifications", []),
        "trace": final.get("trace", []),
    }
