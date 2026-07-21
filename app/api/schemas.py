"""Request/response models for the HTTP layer."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class DisputeSummary(BaseModel):
    id: str
    transaction_id: str
    reason_code: str
    amount_display: str
    status: str
    raised_at: str


class InvestigationResponse(BaseModel):
    case_run_id: str
    dispute_id: str | None = None
    status: str
    error: str | None = None
    # Plain-language facts of the case, for the non-technical view.
    overview: dict[str, Any] | None = None
    risk_score: float | None = None
    risk_band: str | None = None
    decision: str | None = None
    decided_by: str | None = None
    decision_reasons: list[str] = Field(default_factory=list)
    adjudication: dict[str, Any] | None = None
    triggered_signals: list[str] = Field(default_factory=list)
    signals: list[dict[str, Any]] = Field(default_factory=list)
    action_result: dict[str, Any] | None = None
    fraud_alert: dict[str, Any] | None = None
    notifications: list[dict[str, Any]] = Field(default_factory=list)
    trace: list[dict[str, Any]] = Field(default_factory=list)


class HumanDecisionRequest(BaseModel):
    decision: Literal["approve_refund", "reject"]
    notes: str = Field(default="", max_length=2000)
    reviewer: str = Field(default="unknown", max_length=120)


class AuditEventOut(BaseModel):
    sequence: int
    agent: str
    step: str
    tool: str | None
    latency_ms: int
    created_at: str
    payload: dict[str, Any] | list[Any] | str


class CaseDetail(BaseModel):
    case_run_id: str
    dispute_id: str
    status: str
    risk_score: float | None
    risk_band: str | None
    decision: str | None
    decided_by: str | None
    summary: str | None
    started_at: str
    finished_at: str | None
    paused_at_node: str | None
    events: list[AuditEventOut]
