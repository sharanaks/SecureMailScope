"""
Orchestrates a full passive scan of a domain: SPF, DMARC, DKIM, MX, TLS,
Certificate. Pure data collection + rule-based scoring — no AI here.
"""
import re
from app.scanner import dns_checks, tls_checks, scoring

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_domain(domain: str) -> str:
    """Basic sanity validation. Raises ValueError on invalid input."""
    domain = domain.strip().lower()
    domain = domain.removeprefix("http://").removeprefix("https://").split("/")[0]
    if not domain or not DOMAIN_RE.match(domain):
        raise ValueError(f"'{domain}' does not look like a valid domain name.")
    return domain


def run_full_scan(domain: str, dkim_selector: str | None, common_selectors: list[str]) -> dict:
    """
    Run every passive check against `domain` and return:
    {
      "domain": str,
      "findings": [ {check, status, evidence, ...}, ... ],   # flat, for scoring
      "checks_detail": {...},                                 # raw detail per check
      "scoring": { ... }                                      # output of scoring.score_findings
    }
    """
    domain = validate_domain(domain)

    selectors = [dkim_selector] if dkim_selector else list(common_selectors)

    spf_result = dns_checks.check_spf(domain)
    dmarc_result = dns_checks.check_dmarc(domain)
    dkim_result = dns_checks.check_dkim(domain, selectors)
    mx_result = dns_checks.check_mx(domain)

    mx_hosts = [r["host"] for r in mx_result.get("records", [])]
    tls_result = tls_checks.check_tls_and_certificate(mx_hosts)
    cert_result = tls_result.pop("cert_check")

    # DKIM: never FAIL when inconclusive — WARNING is the max downside per spec.
    if dkim_result["status"] == "FAIL":
        dkim_result["status"] = "WARNING"

    findings = [
        {"check": "SPF", "status": spf_result["status"], "evidence": spf_result["evidence"]},
        {"check": "DKIM", "status": dkim_result["status"], "evidence": dkim_result["evidence"]},
        {"check": "DMARC", "status": dmarc_result["status"], "evidence": dmarc_result["evidence"]},
        {"check": "MX", "status": mx_result["status"], "evidence": mx_result["evidence"]},
        {"check": "TLS", "status": tls_result["status"], "evidence": tls_result["evidence"]},
        {"check": "Certificate", "status": cert_result["status"], "evidence": cert_result["evidence"]},
    ]

    score_output = scoring.score_findings(findings)

    return {
        "domain": domain,
        "findings": findings,
        "checks_detail": {
            "spf": spf_result,
            "dmarc": dmarc_result,
            "dkim": dkim_result,
            "mx": mx_result,
            "tls": tls_result,
            "certificate": cert_result,
        },
        "scoring": score_output,
    }
