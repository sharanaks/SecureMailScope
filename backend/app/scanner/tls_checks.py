"""
Passive TLS / certificate inspection.

This module makes a single outbound TLS handshake to inspect what
certificate a host presents and what protocol it negotiates. It does
NOT attempt any exploitation, does not send email, and does not
authenticate against the SMTP server — it just opens a TCP+TLS
connection (using SMTP STARTTLS where relevant) and reads the
certificate metadata, then closes the connection.
"""
import socket
import ssl
import smtplib
from datetime import datetime, timezone


CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _parse_cert_dates(cert: dict):
    not_before = datetime.strptime(cert["notBefore"], CERT_DATE_FMT).replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(cert["notAfter"], CERT_DATE_FMT).replace(tzinfo=timezone.utc)
    return not_before, not_after


def _cert_common_name(name_tuples):
    """cert['subject'] / cert['issuer'] are tuples of tuples like (('commonName','x'),)."""
    for rdn in name_tuples:
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def inspect_host_tls(host: str, port: int = 443, timeout: float = 6.0, use_starttls_smtp: bool = False) -> dict:
    """
    Connect to host:port and inspect the TLS certificate.
    If use_starttls_smtp is True, negotiate STARTTLS over an SMTP session
    (used for mail server ports 25/587) instead of a bare TLS handshake.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # We want to *inspect* the cert even if untrusted, not reject it

    try:
        if use_starttls_smtp:
            smtp = smtplib.SMTP(timeout=timeout)
            smtp.connect(host, port)
            smtp.ehlo()
            if not smtp.has_extn("starttls"):
                smtp.quit()
                return {
                    "host": host, "port": port, "tls_available": False,
                    "error": "Server does not advertise STARTTLS support.",
                }
            raw_sock = smtp.sock
            tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version()
            cipher = tls_sock.cipher()
            tls_sock.close()
        else:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    protocol = tls_sock.version()
                    cipher = tls_sock.cipher()
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError, smtplib.SMTPException) as e:
        return {
            "host": host, "port": port, "tls_available": False,
            "error": str(e),
        }

    if not cert:
        return {
            "host": host, "port": port, "tls_available": True,
            "certificate_available": False,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "note": "TLS handshake succeeded but no certificate metadata was returned "
                    "(verification was disabled to allow inspection of self-signed certs).",
        }

    not_before, not_after = _parse_cert_dates(cert)
    now = datetime.now(timezone.utc)
    days_remaining = (not_after - now).days

    subject_cn = _cert_common_name(cert.get("subject", ()))
    issuer_cn = _cert_common_name(cert.get("issuer", ()))
    san_list = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    hostname_match = host in san_list or host == subject_cn or any(
        san.startswith("*.") and host.endswith(san[1:]) for san in san_list
    )

    return {
        "host": host,
        "port": port,
        "tls_available": True,
        "certificate_available": True,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        "subject": subject_cn,
        "issuer": issuer_cn,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "expired": days_remaining < 0,
        "hostname_match": hostname_match,
        "san": san_list,
    }


def check_tls_and_certificate(mx_hosts: list[str]) -> dict:
    """
    Run TLS/certificate inspection against the mail servers for a domain.
    Tries SMTP STARTTLS on port 25, then 587, for each MX host, stopping
    at the first host that responds successfully.
    """
    if not mx_hosts:
        return {
            "check": "TLS",
            "status": "FAIL",
            "evidence": "No mail servers available to test (no MX records).",
            "cert_check": {
                "check": "Certificate",
                "status": "FAIL",
                "evidence": "No mail servers available to inspect a certificate on.",
            },
        }

    last_result = None
    for host in mx_hosts:
        for port in (25, 587):
            result = inspect_host_tls(host, port=port, use_starttls_smtp=True)
            last_result = result
            if result.get("tls_available"):
                break
        if last_result and last_result.get("tls_available"):
            break

    if not last_result or not last_result.get("tls_available"):
        error = last_result.get("error", "unknown error") if last_result else "no hosts tried"
        return {
            "check": "TLS",
            "status": "FAIL",
            "evidence": f"Could not establish TLS/STARTTLS with any mail server. Last error: {error}",
            "raw": last_result,
            "cert_check": {
                "check": "Certificate",
                "status": "FAIL",
                "evidence": "No certificate available — TLS connection failed.",
            },
        }

    tls_status = "PASS"
    tls_evidence = (
        f"STARTTLS negotiated with {last_result['host']}:{last_result['port']} "
        f"using {last_result.get('protocol')}."
    )
    if last_result.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        tls_status = "FAIL"
        tls_evidence += " Outdated/insecure protocol version negotiated."
    elif last_result.get("protocol") == "TLSv1.2":
        tls_status = "WARNING"
        tls_evidence += " TLS 1.2 is acceptable but TLS 1.3 is recommended."

    if not last_result.get("certificate_available"):
        cert_check = {
            "check": "Certificate",
            "status": "WARNING",
            "evidence": "TLS handshake succeeded but certificate metadata could not be retrieved.",
        }
    else:
        if last_result.get("expired"):
            cert_status = "FAIL"
            cert_evidence = f"Certificate for {last_result['host']} EXPIRED on {last_result['not_after']}."
        elif last_result.get("days_remaining", 999) < 14:
            cert_status = "WARNING"
            cert_evidence = f"Certificate expires soon ({last_result['days_remaining']} days remaining)."
        elif not last_result.get("hostname_match"):
            cert_status = "WARNING"
            cert_evidence = (
                f"Certificate does not clearly match hostname {last_result['host']} "
                f"(subject: {last_result.get('subject')}, SAN: {last_result.get('san')})."
            )
        else:
            cert_status = "PASS"
            cert_evidence = (
                f"Valid certificate for {last_result['host']} issued by {last_result.get('issuer')}, "
                f"expiring {last_result['not_after']} ({last_result['days_remaining']} days remaining)."
            )
        cert_check = {
            "check": "Certificate",
            "status": cert_status,
            "evidence": cert_evidence,
            "issuer": last_result.get("issuer"),
            "subject": last_result.get("subject"),
            "not_after": last_result.get("not_after"),
            "hostname_match": last_result.get("hostname_match"),
        }

    return {
        "check": "TLS",
        "status": tls_status,
        "evidence": tls_evidence,
        "raw": last_result,
        "cert_check": cert_check,
    }
