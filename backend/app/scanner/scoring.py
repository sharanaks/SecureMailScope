"""
Deterministic, rule-based risk scoring engine.

PASS:
    Verified secure.

WARNING:
    Verified issue that deserves attention.

FAIL:
    Confirmed security failure.

INCONCLUSIVE:
    The scanner could not reliably determine the result.
    No score deduction is applied.

AI never influences this score.
"""

WEIGHTS = {
    "SPF": {
        "WARNING": 5,
        "FAIL": 15,
    },

    "DKIM": {
        "WARNING": 5,
        "FAIL": 10,
    },

    "DMARC": {
        "WARNING": 8,
        "FAIL": 20,
    },

    "MX": {
        "WARNING": 0,
        "FAIL": 25,
    },

    "TLS": {
        "WARNING": 8,
        "FAIL": 20,
    },

    "Certificate": {
        "WARNING": 6,
        "FAIL": 15,
    },
}


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

    total_deduction = 0

    severities = []

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for f in findings:

        check = f["check"]
        status = f["status"]

        weights = WEIGHTS.get(
            check,
            {
                "WARNING": 5,
                "FAIL": 10,
            }
        )

        # --------------------------------------------------
        # PASS
        # --------------------------------------------------

        if status == "PASS":

            deduction = 0
            severity = None

        # --------------------------------------------------
        # INCONCLUSIVE
        # --------------------------------------------------

        elif status == "INCONCLUSIVE":

            # Cannot verify != confirmed failure.
            deduction = 0
            severity = None

        # --------------------------------------------------
        # WARNING
        # --------------------------------------------------

        elif status == "WARNING":

            deduction = weights["WARNING"]

            severity = SEVERITY_MAP.get(
                (check, "WARNING"),
                "Low"
            )

        # --------------------------------------------------
        # FAIL
        # --------------------------------------------------

        elif status == "FAIL":

            deduction = weights["FAIL"]

            severity = SEVERITY_MAP.get(
                (check, "FAIL"),
                "High"
            )

        else:

            # Unknown scanner state.
            # Never punish the user for an undefined state.
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

    score = max(
        0,
        min(
            100,
            100 - total_deduction
        )
    )

    return {
        "score": score,
        "total_deductions": total_deduction,
        "severities": severities,
        "counts": counts,
    }