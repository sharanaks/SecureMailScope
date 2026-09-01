"""
Report generation + SHA-256 integrity hashing/verification.

The "canonical report" is a plain dict with a fixed key order and no
volatile fields (no "generated_at_wall_clock_ns" style noise), so that
hashing it is stable and reproducible. We serialize with
json.dumps(..., sort_keys=True) to get a deterministic byte string
before hashing.
"""
import hashlib
import json
from datetime import datetime, timezone


def build_canonical_report(assessment_id: str, domain: str, created_at: str,
                            scoring_output: dict, checks_detail: dict,
                            ai_explanation: dict) -> dict:
    """Build the canonical report dict that gets hashed and stored."""
    return {
        "assessment_id": assessment_id,
        "domain": domain,
        "generated_at": created_at,
        "overall_score": scoring_output["score"],
        "severity_counts": scoring_output["counts"],
        "checks": [
            {
                "check": s["check"],
                "status": s["status"],
                "severity": s["severity"],
                "evidence": s["evidence"],
            }
            for s in scoring_output["severities"]
        ],
        "ai_explanation": {
            "source": ai_explanation.get("source"),
            "overall_summary": ai_explanation.get("overall_summary"),
            "per_finding": ai_explanation.get("per_finding"),
        },
        "disclaimer": (
            "This report reflects only passive, public DNS/TLS checks performed at the time "
            "listed above. It is not a comprehensive security audit and does not guarantee the "
            "absence of vulnerabilities. Scans should only be run against domains you own or are "
            "authorized to assess."
        ),
    }


def canonical_bytes(report: dict) -> bytes:
    """Deterministic byte representation of a report for hashing."""
    return json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hash_report(report: dict) -> str:
    """Return the SHA-256 hex digest of the canonical report."""
    return hashlib.sha256(canonical_bytes(report)).hexdigest()


def verify_report(report: dict, expected_hash: str) -> dict:
    """
    Recompute the hash of `report` and compare against `expected_hash`
    (the hash stored at generation time / anchored on-chain).
    """
    actual_hash = hash_report(report)
    verified = actual_hash == expected_hash
    return {
        "verified": verified,
        "status": "INTEGRITY VERIFIED" if verified else "INTEGRITY FAILED",
        "expected_hash": expected_hash,
        "actual_hash": actual_hash,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
