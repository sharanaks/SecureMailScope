"""
Passive DNS-based email security checks.

All checks here only perform standard DNS *lookups* against public
resolvers. Nothing here sends email, authenticates against any
server, or touches private data. This is safe to run against any
domain, but SecureMailScope should only be used on domains the user
owns or is authorized to assess.
"""
import dns.resolver
import dns.exception

RESOLVER_TIMEOUT = 5.0


def _resolver():
    r = dns.resolver.Resolver()
    r.timeout = RESOLVER_TIMEOUT
    r.lifetime = RESOLVER_TIMEOUT
    return r


def _query_txt(name: str):
    """Return list of decoded TXT record strings for `name`, or [] if none."""
    try:
        answers = _resolver().resolve(name, "TXT")
        records = []
        for rdata in answers:
            # dnspython splits long TXT strings into chunks; join them.
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            records.append(txt)
        return records
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.exception.DNSException:
        return []


def check_spf(domain: str) -> dict:
    """
    Look up the domain's SPF record (a TXT record starting with 'v=spf1').

    Returns a dict with: status (pass/warning/fail), evidence, details.
    """
    txt_records = _query_txt(domain)
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return {
            "check": "SPF",
            "status": "FAIL",
            "evidence": "No SPF TXT record found at domain apex.",
            "raw_records": txt_records,
        }

    if len(spf_records) > 1:
        return {
            "check": "SPF",
            "status": "WARNING",
            "evidence": f"Multiple SPF records found ({len(spf_records)}). "
                        "RFC 7208 permits only one SPF record per domain; "
                        "multiple records cause undefined behavior in mail servers.",
            "raw_records": spf_records,
        }

    record = spf_records[0]
    # Check the "all" mechanism, which governs strictness.
    if "-all" in record:
        status = "PASS"
        note = "Uses '-all' (hard fail) — strict enforcement."
    elif "~all" in record:
        status = "WARNING"
        note = "Uses '~all' (soft fail) — non-compliant mail is flagged but not rejected."
    elif "?all" in record:
        status = "WARNING"
        note = "Uses '?all' (neutral) — provides effectively no enforcement."
    elif "+all" in record:
        status = "FAIL"
        note = "Uses '+all' (pass-all) — allows ANY server to send as this domain."
    else:
        status = "WARNING"
        note = "No explicit 'all' mechanism found; enforcement behavior is unclear."

    return {
        "check": "SPF",
        "status": status,
        "evidence": f"SPF record: {record}. {note}",
        "raw_records": spf_records,
    }


def check_dmarc(domain: str) -> dict:
    """Look up _dmarc.<domain> TXT record and analyze its policy."""
    name = f"_dmarc.{domain}"
    txt_records = _query_txt(name)
    dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return {
            "check": "DMARC",
            "status": "FAIL",
            "evidence": f"No DMARC record found at {name}.",
            "raw_records": txt_records,
        }

    record = dmarc_records[0]
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "").lower()
    pct = tags.get("pct", "100")
    has_rua = "rua" in tags

    if policy == "reject":
        status = "PASS"
        note = "Policy 'reject' — strongest enforcement."
    elif policy == "quarantine":
        status = "WARNING"
        note = "Policy 'quarantine' — non-compliant mail is flagged, not rejected."
    elif policy == "none":
        status = "WARNING"
        note = "Policy 'none' — monitoring only, no enforcement against spoofing."
    else:
        status = "FAIL"
        note = f"Unrecognized or missing policy tag ('p={policy}')."

    if status != "FAIL" and pct != "100":
        status = "WARNING"
        note += f" Only {pct}% of mail is subject to the policy."

    if not has_rua:
        note += " No aggregate report address ('rua') configured, limiting visibility."

    return {
        "check": "DMARC",
        "status": status,
        "evidence": f"DMARC record: {record}. {note}",
        "raw_records": dmarc_records,
        "policy": policy,
    }


def check_dkim(domain: str, selectors: list[str]) -> dict:
    """
    DKIM requires knowing the selector used by the mail provider, which
    is not discoverable via a single generic DNS query. This checks a
    provided or common list of selectors at <selector>._domainkey.<domain>.
    """
    found = []
    checked = []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        checked.append(selector)
        txt_records = _query_txt(name)
        dkim_records = [r for r in txt_records if "v=dkim1" in r.lower() or "p=" in r.lower()]
        if dkim_records:
            found.append({"selector": selector, "record": dkim_records[0]})

    if found:
        return {
            "check": "DKIM",
            "status": "PASS",
            "evidence": f"DKIM record found for selector(s): {', '.join(f['selector'] for f in found)}.",
            "found_selectors": found,
            "selectors_checked": checked,
        }

    return {
        "check": "DKIM",
        "status": "WARNING",
        "evidence": (
            f"No DKIM record found for the {len(checked)} selector(s) checked "
            f"({', '.join(checked)}). DKIM cannot be conclusively determined "
            "without the mail provider's actual selector — this is a known "
            "limitation of passive DKIM discovery, not necessarily a failure."
        ),
        "found_selectors": [],
        "selectors_checked": checked,
        "inconclusive": True,
    }


def check_mx(domain: str) -> dict:
    """Look up MX records for the domain."""
    try:
        answers = _resolver().resolve(domain, "MX")
        records = sorted(
            [{"priority": r.preference, "host": str(r.exchange).rstrip(".")} for r in answers],
            key=lambda x: x["priority"],
        )
    except dns.resolver.NXDOMAIN:
        return {
            "check": "MX",
            "status": "FAIL",
            "evidence": f"Domain {domain} does not exist (NXDOMAIN).",
            "records": [],
        }
    except dns.resolver.NoAnswer:
        return {
            "check": "MX",
            "status": "FAIL",
            "evidence": "No MX records found. Domain cannot receive mail directly.",
            "records": [],
        }
    except dns.exception.DNSException as e:
        return {
            "check": "MX",
            "status": "FAIL",
            "evidence": f"DNS lookup error: {e}",
            "records": [],
        }

    if not records:
        return {
            "check": "MX",
            "status": "FAIL",
            "evidence": "No MX records found.",
            "records": [],
        }

    return {
        "check": "MX",
        "status": "PASS",
        "evidence": f"{len(records)} MX record(s) found: "
                    + ", ".join(f"{r['host']} (priority {r['priority']})" for r in records),
        "records": records,
    }
