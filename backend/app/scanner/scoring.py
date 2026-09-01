"""
Deterministic, rule-based risk scoring engine.

IMPORTANT: AI never influences this score. Severity and score impact
are derived purely from the check status returned by the scanner
modules, via the fixed table below. This guarantees the score is
reproducible: the same scan inputs always produce the same score.

===========================================================
SCORING FORMULA (documented; also reproduced in README.md)
===========================================================
Start at 100 points.

For each of the 6 checks (SPF, DKIM, DMARC, MX, TLS, Certificate):
    PASS    -> no deduction
    WARNING -> deduct the check's WARNING weight
    FAIL    -> deduct the check's FAIL weight

Deduction weights (points):

    Check         WARNING   FAIL
    -----         -------   ----
    SPF              5        15
    DKIM             5        10   (inconclusive DKIM is treated as WARNING, never FAIL)
    DMARC            8        20
    MX               0        25   (MX has no WARNING state)
    TLS              8        20
    Certificate      6        15

Final score = max(0, 100 - total_deductions), clamped to [0, 100].

Severity labels shown on the dashboard (Critical/High/Medium/Low) are
assigned per-finding using the table in `SEVERITY_MAP` below, and are
also fixed/deterministic — never produced by the AI.
"""

WEIGHTS = {
    "SPF": {"WARNING": 5, "FAIL": 15},
    "DKIM": {"WARNING": 5, "FAIL": 10},
    "DMARC": {"WARNING": 8, "FAIL": 20},
    "MX": {"WARNING": 0, "FAIL": 25},
    "TLS": {"WARNING": 8, "FAIL": 20},
    "Certificate": {"WARNING": 6, "FAIL": 15},
}

# Maps (check, status) -> severity label shown to the user.
SEVERITY_MAP = {
    ("SPF", "FAIL"): "High",
    ("SPF", "WARNING"): "Medium",
    ("DKIM", "FAIL"): "Medium",
    ("DKIM", "WARNING"): "Low",
    ("DMARC", "FAIL"): "Critical",
    ("DMARC", "WARNING"): "Medium",
    ("MX", "FAIL"): "Critical",
    ("TLS", "FAIL"): "High",
    ("TLS", "WARNING"): "Medium",
    ("Certificate", "FAIL"): "High",
    ("Certificate", "WARNING"): "Low",
}


def score_findings(findings: list[dict]) -> dict:
    """
    findings: list of dicts each with at least {"check": str, "status": "PASS"|"WARNING"|"FAIL"}
    Returns: {
        "score": int 0-100,
        "total_deductions": int,
        "severities": [{"check", "status", "severity", "deduction"}...],
        "counts": {"critical": n, "high": n, "medium": n, "low": n}
    }
    """
    total_deduction = 0
    severities = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings:
        check = f["check"]
        status = f["status"]
        weights = WEIGHTS.get(check, {"WARNING": 5, "FAIL": 10})

        if status == "PASS":
            deduction = 0
            severity = None
        elif status == "WARNING":
            deduction = weights["WARNING"]
            severity = SEVERITY_MAP.get((check, "WARNING"), "Low")
        elif status == "FAIL":
            deduction = weights["FAIL"]
            severity = SEVERITY_MAP.get((check, "FAIL"), "High")
        else:
            deduction = 0
            severity = None

        total_deduction += deduction
        if severity:
            counts[severity.lower()] += 1

        severities.append({
            "check": check,
            "status": status,
            "severity": severity,
            "deduction": deduction,
            "evidence": f.get("evidence", ""),
        })

    score = max(0, min(100, 100 - total_deduction))

    return {
        "score": score,
        "total_deductions": total_deduction,
        "severities": severities,
        "counts": counts,
    }
