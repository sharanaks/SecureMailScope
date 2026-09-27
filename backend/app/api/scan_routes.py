import os
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from app.database.db import get_cursor
from app.scanner.orchestrator import run_full_scan
from app.ai.explainer import explain_findings, chat_with_claude
from app.services.report import build_canonical_report, hash_report, verify_report
from app.api.models import ScanRequest, VerifyReportRequest
from app.api.auth_routes import get_optional_user


router = APIRouter(prefix="/api", tags=["scan"])


# ---------------------------------------------------------------------
# Request model for AI Assistant
# ---------------------------------------------------------------------

class ChatRequest(BaseModel):
    question: str
    assessment_id: str | None = None


def _common_selectors():
    raw = os.getenv(
        "DKIM_COMMON_SELECTORS",
        "default,selector1,selector2,google,k1,mail,dkim,smtp"
    )

    return [
        s.strip()
        for s in raw.split(",")
        if s.strip()
    ]


# ---------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------

@router.get("/health")
def health():
    return {
        "status": "ok",
        "service": "SecureMailScope backend"
    }


# ---------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------

@router.post("/scan")
def scan(
    payload: ScanRequest,
    user: dict | None = Depends(get_optional_user)
):

    try:
        result = run_full_scan(
            payload.domain,
            payload.dkim_selector,
            _common_selectors()
        )

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    assessment_id = str(uuid.uuid4())

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    scoring_output = result["scoring"]

    # Existing Claude explanation feature
    ai_result = explain_findings(
        result["findings"],
        scoring_output["score"],
        scoring_output["counts"],
        result["domain"]
    )

    report = build_canonical_report(
        assessment_id,
        result["domain"],
        created_at,
        scoring_output,
        result["checks_detail"],
        ai_result
    )

    report_hash = hash_report(report)

    user_id = int(user["sub"]) if user else None

    with get_cursor(commit=True) as cur:

        cur.execute(
            """INSERT INTO assessments
               (id, user_id, domain, created_at, score, raw_findings_json, checks_json,
                ai_explanation_json, ai_source, report_json, report_hash, blockchain_status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'not_anchored')""",
            (
                assessment_id,
                user_id,
                result["domain"],
                created_at,
                scoring_output["score"],
                json.dumps(result["findings"]),
                json.dumps(result["checks_detail"]),
                json.dumps(ai_result),
                ai_result.get("source"),
                json.dumps(report),
                report_hash,
            )
        )

    return {
        "assessment_id": assessment_id,
        "domain": result["domain"],
        "created_at": created_at,
        "score": scoring_output["score"],
        "counts": scoring_output["counts"],
        "checks_detail": result["checks_detail"],
        "severities": scoring_output["severities"],
        "ai_explanation": ai_result,
        "report": report,
        "report_hash": report_hash,
        "blockchain_status": "not_anchored",
    }


# ---------------------------------------------------------------------
# Assessment list
# ---------------------------------------------------------------------

def _row_to_assessment_summary(row) -> dict:

    return {
        "assessment_id": row["id"],
        "domain": row["domain"],
        "created_at": row["created_at"],
        "score": row["score"],
        "blockchain_status": row["blockchain_status"],
    }


@router.get("/assessments")
def list_assessments(
    user: dict | None = Depends(get_optional_user)
):

    with get_cursor() as cur:

        if user:

            cur.execute(
                "SELECT * FROM assessments "
                "WHERE user_id = ? "
                "ORDER BY created_at DESC",
                (int(user["sub"]),)
            )

        else:

            cur.execute(
                "SELECT * FROM assessments "
                "ORDER BY created_at DESC "
                "LIMIT 50"
            )

        rows = cur.fetchall()

    return [
        _row_to_assessment_summary(r)
        for r in rows
    ]


# ---------------------------------------------------------------------
# Get assessment
# ---------------------------------------------------------------------

def _get_assessment_row(
    assessment_id: str
):

    with get_cursor() as cur:

        cur.execute(
            "SELECT * FROM assessments WHERE id = ?",
            (assessment_id,)
        )

        row = cur.fetchone()

    if not row:

        raise HTTPException(
            status_code=404,
            detail="Assessment not found."
        )

    return row


@router.get("/assessments/{assessment_id}")
def get_assessment(
    assessment_id: str
):

    row = _get_assessment_row(
        assessment_id
    )

    return {
        "assessment_id": row["id"],
        "domain": row["domain"],
        "created_at": row["created_at"],
        "score": row["score"],
        "findings": json.loads(row["raw_findings_json"]),
        "checks_detail": json.loads(row["checks_json"]),
        "ai_explanation": (
            json.loads(row["ai_explanation_json"])
            if row["ai_explanation_json"]
            else None
        ),
        "ai_source": row["ai_source"],
        "report": (
            json.loads(row["report_json"])
            if row["report_json"]
            else None
        ),
        "report_hash": row["report_hash"],
        "blockchain_status": row["blockchain_status"],
        "blockchain_tx_hash": row["blockchain_tx_hash"],
    }


# ---------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------

@router.get("/reports/{assessment_id}")
def get_report(
    assessment_id: str
):

    row = _get_assessment_row(
        assessment_id
    )

    return {
        "assessment_id": row["id"],
        "report": (
            json.loads(row["report_json"])
            if row["report_json"]
            else None
        ),
        "report_hash": row["report_hash"],
        "blockchain_status": row["blockchain_status"],
        "blockchain_tx_hash": row["blockchain_tx_hash"],
    }


# ---------------------------------------------------------------------
# Verify report
# ---------------------------------------------------------------------

@router.post("/reports/{assessment_id}/verify")
def verify_report_endpoint(
    assessment_id: str,
    payload: VerifyReportRequest | None = None
):

    """
    Verify report integrity.

    If a report body is supplied in the request,
    it is hashed and compared to the stored hash.

    Otherwise, the stored report is re-hashed and
    compared against the stored hash.
    """

    row = _get_assessment_row(
        assessment_id
    )

    stored_hash = row["report_hash"]

    if not stored_hash:

        raise HTTPException(
            status_code=400,
            detail="This assessment has no stored report hash yet."
        )

    report_to_check = (
        payload.report
        if (payload and payload.report)
        else json.loads(row["report_json"])
    )

    result = verify_report(
        report_to_check,
        stored_hash
    )

    result["assessment_id"] = assessment_id

    return result


# ---------------------------------------------------------------------
# NEW: AI Security Assistant
# ---------------------------------------------------------------------

@router.post("/chat")
def chat(
    payload: ChatRequest,
    user: dict | None = Depends(get_optional_user)
):

    question = payload.question.strip()

    if not question:

        raise HTTPException(
            status_code=400,
            detail="Question cannot be empty."
        )

    context = None

    # ---------------------------------------------------------------
    # If an assessment ID is supplied, load that scan's information.
    # This allows Claude to answer questions about the actual scan.
    # ---------------------------------------------------------------

    if payload.assessment_id:

        row = _get_assessment_row(
            payload.assessment_id
        )

        context = {
            "assessment_id": row["id"],
            "domain": row["domain"],
            "score": row["score"],
            "findings": json.loads(
                row["raw_findings_json"]
            ),
            "checks_detail": json.loads(
                row["checks_json"]
            ),
        }

    # ---------------------------------------------------------------
    # Send question to Claude
    # ---------------------------------------------------------------

    answer = chat_with_claude(
        question,
        context
    )

    if answer is None:

        raise HTTPException(
            status_code=503,
            detail=(
                "Claude AI is currently unavailable. "
                "Please check your Anthropic API key and internet connection."
            )
        )

    return {
        "answer": answer,
        "model": "Claude Sonnet 4.5",
    }