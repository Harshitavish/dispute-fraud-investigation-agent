"""FastAPI surface.

The HTTP layer is deliberately thin: it validates input, calls the graph, and
serialises the result. All the interesting behaviour lives in app/agents.

Run it with:  uvicorn app.api.main:app --reload
Docs at:      http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.graph import pending_node, resume_investigation, start_investigation
from app.api.schemas import (
    AuditEventOut,
    CaseDetail,
    DisputeSummary,
    HumanDecisionRequest,
    InvestigationResponse,
)
from app.config import get_settings
from app.db.models import AuditEvent, CaseRun, CaseStatus, Dispute
from app.db.session import get_session, init_db
from app.tools.sql_tools import fetch_dispute, list_open_disputes

settings = get_settings()

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(
    lifespan=lifespan,
    title=settings.api_title,
    version=settings.api_version,
    description=(
        "Multi-agent system that investigates payment disputes end to end: "
        "retrieves context, scores fraud risk, decides, acts, and notifies -- "
        "with a full audit trail and human-in-the-loop escalation."
    ),
)


STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """The operator console. Mounted at the root; the API lives beside it."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", tags=["ops"])
def health() -> dict[str, Any]:
    from app.agents.nodes import _llm

    return {
        "status": "ok",
        "llm": "claude" if _llm.available else "rules_fallback",
        "model": settings.llm_model if _llm.available else None,
        "email_mode": "smtp" if settings.smtp_enabled else "dry_run",
    }


@app.get("/disputes", response_model=list[DisputeSummary], tags=["disputes"])
def get_open_disputes(session: Session = Depends(get_session)) -> list[dict[str, Any]]:
    return list_open_disputes(session)


@app.get("/disputes/{dispute_id}", tags=["disputes"])
def get_dispute(dispute_id: str, session: Session = Depends(get_session)) -> dict[str, Any]:
    result = fetch_dispute(session, dispute_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Dispute {dispute_id} not found")
    return result


@app.post(
    "/disputes/{dispute_id}/investigate",
    response_model=InvestigationResponse,
    tags=["agents"],
    summary="Run the full multi-agent investigation",
)
def investigate(dispute_id: str, session: Session = Depends(get_session)) -> dict[str, Any]:
    """Fetcher -> Threat Analyst -> Policy -> Action -> Communicator.

    Returns a completed case, or `status: awaiting_human` when the graph has
    paused for review. Resume a paused case via POST /cases/{id}/decision.
    """
    if session.get(Dispute, dispute_id) is None:
        raise HTTPException(status_code=404, detail=f"Dispute {dispute_id} not found")

    try:
        return start_investigation(dispute_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=500, detail=f"Investigation failed: {type(exc).__name__}: {exc}"
        ) from exc


@app.post(
    "/cases/{case_run_id}/decision",
    response_model=InvestigationResponse,
    tags=["agents"],
    summary="Submit a human decision and resume a paused case",
)
def submit_decision(
    case_run_id: str, body: HumanDecisionRequest, session: Session = Depends(get_session)
) -> dict[str, Any]:
    run = session.get(CaseRun, case_run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Case {case_run_id} not found")
    if run.status != CaseStatus.AWAITING_HUMAN:
        raise HTTPException(
            status_code=409,
            detail=f"Case {case_run_id} is {run.status.value}, not awaiting review.",
        )

    notes = f"[{body.reviewer}] {body.notes}".strip()
    try:
        return resume_investigation(case_run_id, body.decision, notes)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/cases", tags=["cases"])
def list_cases(session: Session = Depends(get_session), limit: int = 50) -> list[dict[str, Any]]:
    runs = session.scalars(
        select(CaseRun).order_by(CaseRun.started_at.desc()).limit(limit)
    ).all()
    return [
        {
            "case_run_id": r.id,
            "dispute_id": r.dispute_id,
            "status": r.status.value,
            "risk_score": r.risk_score,
            "risk_band": r.risk_band,
            "decision": r.decision,
            "decided_by": r.decided_by,
            "started_at": r.started_at.isoformat(),
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        }
        for r in runs
    ]


@app.get(
    "/cases/{case_run_id}",
    response_model=CaseDetail,
    tags=["cases"],
    summary="Full audit trail for one investigation",
)
def get_case(case_run_id: str, session: Session = Depends(get_session)) -> dict[str, Any]:
    run = session.get(CaseRun, case_run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Case {case_run_id} not found")

    events = session.scalars(
        select(AuditEvent)
        .where(AuditEvent.case_run_id == case_run_id)
        .order_by(AuditEvent.sequence)
    ).all()

    def _payload(raw: str) -> Any:
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return raw

    return {
        "case_run_id": run.id,
        "dispute_id": run.dispute_id,
        "status": run.status.value,
        "risk_score": run.risk_score,
        "risk_band": run.risk_band,
        "decision": run.decision,
        "decided_by": run.decided_by,
        "summary": run.summary,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "paused_at_node": pending_node(case_run_id),
        "events": [
            AuditEventOut(
                sequence=e.sequence,
                agent=e.agent,
                step=e.step,
                tool=e.tool,
                latency_ms=e.latency_ms,
                created_at=e.created_at.isoformat(),
                payload=_payload(e.payload),
            )
            for e in events
        ],
    }
