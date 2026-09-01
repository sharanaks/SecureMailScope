"""
AI explanation layer.

CRITICAL DESIGN RULE: the AI never decides severity or score — that is
entirely owned by app.scanner.scoring (a deterministic rule engine).
The AI's only job is to translate already-decided findings into plain
language: what it means, why it matters, and what to do about it.

If ANTHROPIC_API_KEY is not configured, `explain_findings` transparently
falls back to a deterministic, template-based explanation generator so
the demo works fully offline / without any API key. The `source` field
in the returned dict tells the caller which path was used.
"""
import os
import json
import requests

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"


def _api_key():
    return os.getenv("ANTHROPIC_API_KEY", "").strip()


def _model():
    return os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")


# ---------------------------------------------------------------------
# Deterministic fallback templates (used when no API key is present)
# ---------------------------------------------------------------------
_TEMPLATES = {
    ("SPF", "FAIL"): {
        "why_it_matters": "Without a valid SPF record, mail servers cannot verify that email "
                           "claiming to be from your domain was actually sent by an authorized "
                           "server. This makes spoofing and phishing using your domain name easy.",
        "recommendation": "Publish an SPF TXT record listing your authorized sending servers, "
                           "ending with '-all' to hard-fail unauthorized senders.",
    },
    ("SPF", "WARNING"): {
        "why_it_matters": "Your SPF record exists but does not strictly enforce which servers "
                           "may send mail as your domain, leaving room for spoofed messages to "
                           "be delivered instead of rejected.",
        "recommendation": "Tighten your SPF policy to '-all' once you have confirmed all "
                           "legitimate sending sources are listed, and remove duplicate records "
                           "if present.",
    },
    ("DKIM", "WARNING"): {
        "why_it_matters": "DKIM allows receiving mail servers to cryptographically verify that a "
                           "message was not altered in transit and originated from an authorized "
                           "source. Without a discoverable DKIM record, this protection may be "
                           "missing or simply uses a selector this scan did not check.",
        "recommendation": "Confirm DKIM signing is enabled with your mail provider and supply the "
                           "correct selector to this tool, or check your provider's admin console "
                           "for DKIM setup instructions.",
    },
    ("DMARC", "FAIL"): {
        "why_it_matters": "Without DMARC, there is no policy telling receiving mail servers what "
                           "to do with messages that fail SPF/DKIM checks, and no reporting "
                           "channel to alert you to abuse of your domain.",
        "recommendation": "Publish a DMARC record at _dmarc.<domain> starting with 'p=none' while "
                           "you gather reports, then move to 'p=quarantine' and eventually "
                           "'p=reject' as confidence increases.",
    },
    ("DMARC", "WARNING"): {
        "why_it_matters": "Your DMARC policy is not yet set to fully reject unauthorized mail, "
                           "which means spoofed messages may still reach recipients' inboxes.",
        "recommendation": "Gradually move your DMARC policy toward 'p=reject' with 'pct=100', and "
                           "ensure an aggregate report address ('rua') is configured for visibility.",
    },
    ("MX", "FAIL"): {
        "why_it_matters": "Without valid MX records, the domain cannot reliably receive email at "
                           "all, or mail may be routed unpredictably.",
        "recommendation": "Configure MX records pointing to your mail provider's designated mail "
                           "servers.",
    },
    ("TLS", "FAIL"): {
        "why_it_matters": "Mail transmitted without modern TLS encryption can be intercepted or "
                           "read in transit, exposing message contents and credentials.",
        "recommendation": "Ensure your mail servers support STARTTLS with TLS 1.2 or newer, and "
                           "disable legacy protocol versions (SSLv3, TLS 1.0/1.1).",
    },
    ("TLS", "WARNING"): {
        "why_it_matters": "Your mail server supports encryption, but using an older TLS version "
                           "than recommended slightly increases exposure to known protocol "
                           "weaknesses.",
        "recommendation": "Upgrade mail server configuration to prefer TLS 1.3 where supported by "
                           "your provider.",
    },
    ("Certificate", "FAIL"): {
        "why_it_matters": "An expired or invalid certificate breaks encrypted mail delivery trust "
                           "and may cause mail clients or servers to reject secure connections.",
        "recommendation": "Renew the TLS certificate immediately and set up automated renewal "
                           "monitoring going forward.",
    },
    ("Certificate", "WARNING"): {
        "why_it_matters": "The certificate is nearing expiration or does not clearly match the "
                           "server hostname, which can cause trust warnings or future outages.",
        "recommendation": "Renew the certificate before expiry and confirm the certificate's "
                           "Subject Alternative Names include the mail server hostname.",
    },
}

_PASS_TEMPLATE = {
    "why_it_matters": "This control is correctly configured and reduces the risk of spoofing, "
                       "interception, or delivery failure.",
    "recommendation": "No action required. Periodically re-verify this control after any change "
                       "to mail infrastructure.",
}


def _fallback_explain_finding(finding: dict) -> dict:
    check, status = finding["check"], finding["status"]
    if status == "PASS":
        tpl = _PASS_TEMPLATE
    else:
        tpl = _TEMPLATES.get((check, status), {
            "why_it_matters": "This finding may affect the domain's email security posture.",
            "recommendation": "Review this control against current best practices for the "
                               "relevant standard.",
        })
    return {
        "check": check,
        "status": status,
        "simple_explanation": f"{check} check result: {status}. {finding.get('evidence', '')}",
        "why_it_matters": tpl["why_it_matters"],
        "recommendation": tpl["recommendation"],
    }


def _fallback_overall_summary(score: int, counts: dict, domain: str) -> str:
    if score >= 90:
        tier = "a strong"
    elif score >= 70:
        tier = "a reasonable"
    elif score >= 40:
        tier = "a weak"
    else:
        tier = "a critically weak"

    issues = []
    for label in ("critical", "high", "medium", "low"):
        n = counts.get(label, 0)
        if n:
            issues.append(f"{n} {label}")

    issue_text = ", ".join(issues) if issues else "no outstanding"

    return (
        f"{domain} scored {score}/100, indicating {tier} email security posture based on this "
        f"passive scan. The scan identified {issue_text} severity finding(s) across SPF, DKIM, "
        f"DMARC, MX, and TLS/certificate checks. This is not a guarantee of security or the "
        f"absence of vulnerabilities — it reflects only what could be observed via public, "
        f"passive DNS and TLS checks at scan time. Address findings in order of severity, "
        f"starting with Critical and High items."
    )


def _fallback_explain(findings: list[dict], score: int, counts: dict, domain: str) -> dict:
    return {
        "source": "fallback_template",
        "per_finding": [_fallback_explain_finding(f) for f in findings],
        "overall_summary": _fallback_overall_summary(score, counts, domain),
    }


# ---------------------------------------------------------------------
# LLM-backed explanation (used only if ANTHROPIC_API_KEY is set)
# ---------------------------------------------------------------------
def _llm_explain(findings: list[dict], score: int, counts: dict, domain: str) -> dict | None:
    api_key = _api_key()
    if not api_key:
        return None

    system_prompt = (
        "You are a cybersecurity assistant embedded in an automated email-security scanner. "
        "A deterministic rule engine has ALREADY decided each finding's status and severity. "
        "Your ONLY job is to explain findings in plain language: what it means, why it matters, "
        "and a recommended fix. Do NOT invent new findings, do NOT change severity, do NOT claim "
        "a domain is '100% secure' or make absolute guarantees. Respond ONLY with strict JSON, "
        "no markdown fences, no preamble, matching this schema exactly:\n"
        '{"per_finding": [{"check": str, "simple_explanation": str, "why_it_matters": str, '
        '"recommendation": str}, ...], "overall_summary": str}'
    )

    user_prompt = json.dumps({
        "domain": domain,
        "overall_score": score,
        "severity_counts": counts,
        "findings": findings,
    })

    try:
        resp = requests.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": _model(),
                "max_tokens": 1500,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        raw_text = "\n".join(text_blocks).strip()
        raw_text = raw_text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(raw_text)
        parsed["source"] = "llm"
        return parsed
    except Exception:
        # Any failure (network, auth, parsing) -> caller falls back to templates.
        return None


def explain_findings(findings: list[dict], score: int, counts: dict, domain: str) -> dict:
    """
    Returns:
    {
      "source": "llm" | "fallback_template",
      "per_finding": [{"check","simple_explanation","why_it_matters","recommendation"}, ...],
      "overall_summary": str
    }
    """
    llm_result = _llm_explain(findings, score, counts, domain)
    if llm_result:
        return llm_result
    return _fallback_explain(findings, score, counts, domain)
