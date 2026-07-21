"""Shared graph state.

LangGraph threads one dict through every node. Keeping it a TypedDict (rather
than passing objects around) means the whole investigation is serialisable --
which is what makes checkpointing, pausing for a human, and resuming days later
possible.
"""

from __future__ import annotations

from operator import add
from typing import Annotated, Any, Literal, TypedDict

Decision = Literal["auto_refund", "manual_review", "reject_and_flag"]
RiskBand = Literal["LOW", "MEDIUM", "HIGH"]


class CaseState(TypedDict, total=False):
    # --- identity ---
    case_run_id: str
    dispute_id: str

    # --- Fetcher agent output ---
    context: dict[str, Any]
    fetch_error: str | None

    # --- Threat Analyst agent output ---
    signals: list[dict[str, Any]]
    risk_score: float
    risk_band: RiskBand
    adjudication: dict[str, Any]

    # --- Policy engine output ---
    rules_action: Decision
    decision: Decision
    decision_reasons: list[str]
    decided_by: str

    # --- Human-in-the-loop ---
    human_decision: str | None  # "approve_refund" | "reject" | None
    human_notes: str | None

    # --- Action & Communication agent output ---
    action_result: dict[str, Any]
    fraud_alert: dict[str, Any] | None

    # Appended to by several nodes, so they use an additive reducer rather
    # than last-write-wins.
    notifications: Annotated[list[dict[str, Any]], add]
    trace: Annotated[list[dict[str, Any]], add]
