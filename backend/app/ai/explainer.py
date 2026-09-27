"""
AI explanation and chat layer for SecureMailScope.

The AI does NOT decide security score or severity.
Those are calculated by the deterministic scoring engine.

Claude is used for:
1. Explaining scan findings
2. Giving recommendations
3. Answering cybersecurity questions through the AI Assistant

If ANTHROPIC_API_KEY is not configured, scan explanations
fall back to deterministic templates.
"""

import os
import json
import requests


ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"


def _api_key():
    return os.getenv("ANTHROPIC_API_KEY", "").strip()


def _model():
    return os.getenv(
        "ANTHROPIC_MODEL",
        "claude-sonnet-4-5-20250929"
    )


# ---------------------------------------------------------------------
# Deterministic fallback templates
# Used when no API key is present
# ---------------------------------------------------------------------

_TEMPLATES = {
    ("SPF", "FAIL"): {
        "why_it_matters": (
            "Without a valid SPF record, mail servers cannot verify that "
            "email claiming to be from your domain was actually sent by an "
            "authorized server. This makes spoofing and phishing using your "
            "domain name easy."
        ),
        "recommendation": (
            "Publish an SPF TXT record listing your authorized sending "
            "servers, ending with '-all' to hard-fail unauthorized senders."
        ),
    },

    ("SPF", "WARNING"): {
        "why_it_matters": (
            "Your SPF record exists but does not strictly enforce which "
            "servers may send mail as your domain, leaving room for spoofed "
            "messages to be delivered instead of rejected."
        ),
        "recommendation": (
            "Tighten your SPF policy to '-all' once you have confirmed all "
            "legitimate sending sources are listed, and remove duplicate "
            "records if present."
        ),
    },

    ("DKIM", "WARNING"): {
        "why_it_matters": (
            "DKIM allows receiving mail servers to cryptographically verify "
            "that a message was not altered in transit and originated from "
            "an authorized source. Without a discoverable DKIM record, this "
            "protection may be missing or simply uses a selector this scan "
            "did not check."
        ),
        "recommendation": (
            "Confirm DKIM signing is enabled with your mail provider and "
            "supply the correct selector to this tool, or check your "
            "provider's admin console for DKIM setup instructions."
        ),
    },

    ("DMARC", "FAIL"): {
        "why_it_matters": (
            "Without DMARC, there is no policy telling receiving mail "
            "servers what to do with messages that fail SPF/DKIM checks, "
            "and no reporting channel to alert you to abuse of your domain."
        ),
        "recommendation": (
            "Publish a DMARC record at _dmarc.<domain> starting with "
            "'p=none' while you gather reports, then move to 'p=quarantine' "
            "and eventually 'p=reject' as confidence increases."
        ),
    },

    ("DMARC", "WARNING"): {
        "why_it_matters": (
            "Your DMARC policy is not yet set to fully reject unauthorized "
            "mail, which means spoofed messages may still reach recipients' "
            "inboxes."
        ),
        "recommendation": (
            "Gradually move your DMARC policy toward 'p=reject' with "
            "'pct=100', and ensure an aggregate report address ('rua') is "
            "configured for visibility."
        ),
    },

    ("MX", "FAIL"): {
        "why_it_matters": (
            "Without valid MX records, the domain cannot reliably receive "
            "email at all, or mail may be routed unpredictably."
        ),
        "recommendation": (
            "Configure MX records pointing to your mail provider's "
            "designated mail servers."
        ),
    },

    ("TLS", "FAIL"): {
        "why_it_matters": (
            "Mail transmitted without modern TLS encryption can be "
            "intercepted or read in transit, exposing message contents "
            "and credentials."
        ),
        "recommendation": (
            "Ensure your mail servers support STARTTLS with TLS 1.2 or "
            "newer, and disable legacy protocol versions "
            "(SSLv3, TLS 1.0/1.1)."
        ),
    },

    ("TLS", "WARNING"): {
        "why_it_matters": (
            "Your mail server supports encryption, but using an older TLS "
            "version than recommended slightly increases exposure to "
            "known protocol weaknesses."
        ),
        "recommendation": (
            "Upgrade mail server configuration to prefer TLS 1.3 where "
            "supported by your provider."
        ),
    },

    ("Certificate", "FAIL"): {
        "why_it_matters": (
            "An expired or invalid certificate breaks encrypted mail "
            "delivery trust and may cause mail clients or servers to "
            "reject secure connections."
        ),
        "recommendation": (
            "Renew the TLS certificate immediately and set up automated "
            "renewal monitoring going forward."
        ),
    },

    ("Certificate", "WARNING"): {
        "why_it_matters": (
            "The certificate is nearing expiration or does not clearly "
            "match the server hostname, which can cause trust warnings "
            "or future outages."
        ),
        "recommendation": (
            "Renew the certificate before expiry and confirm the "
            "certificate's Subject Alternative Names include the mail "
            "server hostname."
        ),
    },
}


_PASS_TEMPLATE = {
    "why_it_matters": (
        "This control is correctly configured and reduces the risk of "
        "spoofing, interception, or delivery failure."
    ),
    "recommendation": (
        "No action required. Periodically re-verify this control after "
        "any change to mail infrastructure."
    ),
}


# ---------------------------------------------------------------------
# Fallback explanation functions
# ---------------------------------------------------------------------

def _fallback_explain_finding(finding: dict) -> dict:
    check = finding["check"]
    status = finding["status"]

    if status == "PASS":
        tpl = _PASS_TEMPLATE
    else:
        tpl = _TEMPLATES.get(
            (check, status),
            {
                "why_it_matters": (
                    "This finding may affect the domain's email security posture."
                ),
                "recommendation": (
                    "Review this control against current best practices "
                    "for the relevant standard."
                ),
            },
        )

    return {
        "check": check,
        "status": status,
        "simple_explanation": (
            f"{check} check result: {status}. "
            f"{finding.get('evidence', '')}"
        ),
        "why_it_matters": tpl["why_it_matters"],
        "recommendation": tpl["recommendation"],
    }


def _fallback_overall_summary(
    score: int,
    counts: dict,
    domain: str
) -> str:

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
        f"{domain} scored {score}/100, indicating {tier} email security "
        f"posture based on this passive scan. The scan identified "
        f"{issue_text} severity finding(s) across SPF, DKIM, DMARC, MX, "
        f"and TLS/certificate checks. This is not a guarantee of security "
        f"or the absence of vulnerabilities — it reflects only what could "
        f"be observed via public, passive DNS and TLS checks at scan time. "
        f"Address findings in order of severity, starting with Critical "
        f"and High items."
    )


def _fallback_explain(
    findings: list[dict],
    score: int,
    counts: dict,
    domain: str
) -> dict:

    return {
        "source": "fallback_template",
        "per_finding": [
            _fallback_explain_finding(f)
            for f in findings
        ],
        "overall_summary": _fallback_overall_summary(
            score,
            counts,
            domain
        ),
    }


# ---------------------------------------------------------------------
# Claude explanation
# ---------------------------------------------------------------------

def _llm_explain(
    findings: list[dict],
    score: int,
    counts: dict,
    domain: str
) -> dict | None:

    api_key = _api_key()

    if not api_key:
        return None

    system_prompt = (
        "You are a cybersecurity assistant embedded in an automated "
        "email-security scanner. "
        "A deterministic rule engine has ALREADY decided each finding's "
        "status and severity. "
        "Your ONLY job is to explain findings in plain language: "
        "what it means, why it matters, and a recommended fix. "
        "Do NOT invent new findings, do NOT change severity, do NOT claim "
        "a domain is '100% secure' or make absolute guarantees. "
        "Respond ONLY with strict JSON, no markdown fences, no preamble, "
        "matching this schema exactly:\n"
        '{"per_finding": [{"check": str, '
        '"simple_explanation": str, '
        '"why_it_matters": str, '
        '"recommendation": str}, ...], '
        '"overall_summary": str}'
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
                "messages": [
                    {
                        "role": "user",
                        "content": user_prompt,
                    }
                ],
            },
            timeout=20,
        )

        resp.raise_for_status()

        data = resp.json()

        text_blocks = [
            b["text"]
            for b in data.get("content", [])
            if b.get("type") == "text"
        ]

        raw_text = "\n".join(text_blocks).strip()

        raw_text = (
            raw_text
            .removeprefix("```json")
            .removeprefix("```")
            .removesuffix("```")
            .strip()
        )

        parsed = json.loads(raw_text)

        parsed["source"] = "llm"

        return parsed

    except Exception:
        return None


def explain_findings(
    findings: list[dict],
    score: int,
    counts: dict,
    domain: str
) -> dict:

    """
    Explain scan findings using Claude when available.

    Falls back to deterministic templates if Claude is unavailable.
    """

    llm_result = _llm_explain(
        findings,
        score,
        counts,
        domain
    )

    if llm_result:
        return llm_result

    return _fallback_explain(
        findings,
        score,
        counts,
        domain
    )


# ---------------------------------------------------------------------
# AI Security Assistant with offline fallback
# ---------------------------------------------------------------------

def local_chat(question: str, context: dict | None = None) -> str:
    """
    Offline fallback assistant.

    This is used when Claude is unavailable, has no API credits,
    or the API request fails.
    """

    q = question.lower().strip()

    answers = {
        "spf": (
            "SPF stands for Sender Policy Framework. "
            "It is a DNS record that specifies which mail servers are "
            "authorized to send email for a domain. SPF helps reduce "
            "email spoofing."
        ),
        "dkim": (
            "DKIM stands for DomainKeys Identified Mail. "
            "It adds a cryptographic signature to outgoing emails so "
            "receiving mail servers can verify that the message came "
            "from an authorized system and was not modified in transit."
        ),
        "dmarc": (
            "DMARC stands for Domain-based Message Authentication, "
            "Reporting and Conformance. It tells receiving mail servers "
            "what to do when an email fails SPF or DKIM authentication. "
            "Common policies are none, quarantine and reject."
        ),
        "mx": (
            "MX stands for Mail Exchange. MX records specify which mail "
            "servers receive email for a domain. Without valid MX records, "
            "email delivery to the domain may not work correctly."
        ),
        "tls": (
            "TLS stands for Transport Layer Security. It encrypts network "
            "communication so data cannot easily be read while travelling "
            "between systems. SecureMailScope checks TLS/STARTTLS support "
            "for mail servers."
        ),
        "spoof": (
            "Email spoofing is when an attacker makes an email appear to "
            "come from another person's or organization's domain. "
            "SPF, DKIM and DMARC provide important defenses against spoofing."
        ),
        "phishing": (
            "Phishing is a cyberattack where an attacker tries to trick "
            "someone into revealing sensitive information or performing "
            "an unsafe action, often through a fake email, message or website."
        ),
        "blockchain": (
            "Blockchain is used in SecureMailScope to make report integrity "
            "verifiable. The system creates a SHA-256 fingerprint of the "
            "report and anchors that fingerprint on the blockchain. "
            "Later, the report can be hashed again and compared with the "
            "anchored fingerprint."
        ),
        "score": (
            "The SecureMailScope security score is calculated by a "
            "deterministic rule-based scoring engine. It summarizes the "
            "results of the SPF, DKIM, DMARC, MX, TLS and certificate checks. "
            "It is not a guarantee that a domain is completely secure."
        ),
        "securemailscope": (
            "SecureMailScope is an email-security posture assessment system. "
            "It checks publicly observable email-security controls such as "
            "SPF, DKIM, DMARC, MX, TLS and certificates. It then provides "
            "a security score, findings and recommendations."
        ),
        "certificate": (
            "A TLS certificate helps establish the identity of a server "
            "during a secure TLS connection. SecureMailScope checks "
            "certificate information such as expiration and hostname matching "
            "when certificate data can be obtained."
        ),
        "pass": (
            "PASS means the corresponding security control was successfully "
            "detected and met the rule used by SecureMailScope."
        ),
        "fail": (
            "FAIL means the corresponding security control did not meet "
            "the rule used by SecureMailScope. The exact reason is shown "
            "in the finding evidence."
        ),
    }

    specific_questions = [
        ("what is securemailscope", "securemailscope"),
        ("what does securemailscope", "securemailscope"),
        ("what is email spoofing", "spoof"),
        ("what is spoofing", "spoof"),
        ("what is phishing", "phishing"),
        ("what is blockchain", "blockchain"),
        ("why blockchain", "blockchain"),
        ("what is certificate", "certificate"),
        ("what does a certificate", "certificate"),
        ("what is spf", "spf"),
        ("explain spf", "spf"),
        ("what is dkim", "dkim"),
        ("explain dkim", "dkim"),
        ("what is dmarc", "dmarc"),
        ("explain dmarc", "dmarc"),
        ("what is mx", "mx"),
        ("explain mx", "mx"),
        ("what is tls", "tls"),
        ("explain tls", "tls"),
        ("what does pass mean", "pass"),
        ("what is pass", "pass"),
        ("what does fail mean", "fail"),
        ("what is fail", "fail"),
    ]

    for phrase, key in specific_questions:
        if phrase in q:
            return answers[key]

    if "what is my score" in q or "why is my score" in q:
        if context:
            domain = context.get("domain", "the domain")
            score = context.get("score", "unknown")
            return (
                f"The current SecureMailScope assessment for {domain} "
                f"has a score of {score}/100. The score is calculated by "
                "the deterministic rule-based scoring engine from the scan "
                "results. It is not a guarantee that the domain is completely secure."
            )
        return answers["score"]

    if "my scan" in q or "my domain" in q or "my result" in q:
        if context:
            domain = context.get("domain", "the domain")
            score = context.get("score", "unknown")
            return (
                f"The current SecureMailScope assessment for {domain} "
                f"has a score of {score}/100. Open the scan results to see "
                "the individual SPF, DKIM, DMARC, MX, TLS and certificate findings."
            )

    for keyword in (
        "spf", "dkim", "dmarc", "mx", "tls", "certificate",
        "spoof", "phishing", "blockchain", "score", "securemailscope"
    ):
        if keyword in q:
            return answers[keyword]

    return (
        "I can help with SecureMailScope and basic cybersecurity topics "
        "such as SPF, DKIM, DMARC, MX, TLS, certificates, email spoofing, "
        "phishing, security scores and blockchain. "
        "Please ask a question about one of these topics."
    )


def chat_with_claude(
    question: str,
    context: dict | None = None
) -> str | None:
    """
    AI Security Assistant.

    Claude is used when API access is available.
    If Claude is unavailable, the offline local assistant answers instead.
    """

    api_key = _api_key()

    # No API key: use offline assistant.
    if not api_key:
        return local_chat(question, context)

    system_prompt = (
        "You are the AI Security Assistant for SecureMailScope. "
        "You help users understand cybersecurity, email security, "
        "and their SecureMailScope scan results. "
        "Answer clearly and accurately using beginner-friendly language. "
        "You can explain SPF, DKIM, DMARC, MX, TLS, certificates, "
        "email spoofing, phishing, cybersecurity, blockchain, "
        "security scores, and SecureMailScope. "
        "If scan information is provided, use it when answering "
        "questions about the scan. "
        "Do not invent scan findings. "
        "Do not change or recalculate the official SecureMailScope score. "
        "Do not claim that a domain is 100% secure. "
        "Remember that SecureMailScope performs a passive email-security "
        "assessment and is not a complete security audit. "
        "If you do not have enough information, say so clearly."
    )

    user_content = {
        "question": question,
        "scan_context": context,
    }

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
                "max_tokens": 1200,
                "system": system_prompt,
                "messages": [
                    {
                        "role": "user",
                        "content": json.dumps(user_content),
                    }
                ],
            },
            timeout=30,
        )

        resp.raise_for_status()

        data = resp.json()

        text_blocks = [
            block["text"]
            for block in data.get("content", [])
            if block.get("type") == "text"
        ]

        answer = "\n".join(text_blocks).strip()

        if not answer:
            return local_chat(question, context)

        return answer

    except requests.HTTPError as e:
        # Claude may return errors such as "credit balance is too low".
        # Fall back to the offline assistant so the demo still works.
        print("Claude API unavailable:", e)
        if "resp" in locals():
            print("Claude response:", resp.text)
        return local_chat(question, context)

    except Exception as e:
        print("Claude API unavailable:", repr(e))
        return local_chat(question, context)
