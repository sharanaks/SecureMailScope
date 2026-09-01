from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from app.database.db import get_cursor
from app.blockchain.client import blockchain_client

router = APIRouter(prefix="/api/blockchain", tags=["blockchain"])


def _get_assessment_row(assessment_id: str):
    with get_cursor() as cur:
        cur.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return row


@router.post("/anchor/{assessment_id}")
def anchor_assessment(assessment_id: str):
    row = _get_assessment_row(assessment_id)
    if not row["report_hash"]:
        raise HTTPException(status_code=400, detail="Assessment has no report hash to anchor.")

    result = blockchain_client.register_assessment(assessment_id, row["report_hash"])

    if not result["success"]:
        with get_cursor(commit=True) as cur:
            cur.execute(
                "UPDATE assessments SET blockchain_status = 'failed' WHERE id = ?",
                (assessment_id,),
            )
        raise HTTPException(status_code=502, detail=f"Blockchain anchoring failed: {result['error']}")

    now = datetime.now(timezone.utc).isoformat()
    with get_cursor(commit=True) as cur:
        cur.execute(
            """UPDATE assessments
               SET blockchain_status = 'anchored', blockchain_tx_hash = ?, blockchain_timestamp = ?
               WHERE id = ?""",
            (result["tx_hash"], now, assessment_id),
        )

    return {
        "assessment_id": assessment_id,
        "blockchain_status": "anchored",
        "transaction_hash": result["tx_hash"],
        "report_hash": row["report_hash"],
        "anchored_at": now,
    }


@router.get("/status/{assessment_id}")
def blockchain_status(assessment_id: str):
    row = _get_assessment_row(assessment_id)
    response = {
        "assessment_id": assessment_id,
        "blockchain_status": row["blockchain_status"],
        "transaction_hash": row["blockchain_tx_hash"],
        "report_hash": row["report_hash"],
        "anchored_at": row["blockchain_timestamp"],
    }

    if row["blockchain_status"] == "anchored":
        onchain = blockchain_client.get_assessment(assessment_id)
        response["onchain_record"] = onchain if onchain.get("success") else None
        if onchain.get("success"):
            response["onchain_hash_matches"] = onchain["report_hash"] == row["report_hash"]

    return response
