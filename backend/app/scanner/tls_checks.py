"""
Passive TLS / certificate inspection.

This module performs a passive TLS/STARTTLS connection to inspect
mail-server TLS configuration and certificate metadata.

Important:
- A confirmed TLS problem is reported as FAIL.
- A connection timeout/refusal is reported as INCONCLUSIVE.
- We do NOT treat inability to test as proof of a security failure.
"""

import socket
import ssl
import smtplib
from datetime import datetime, timezone


CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _parse_cert_dates(cert: dict):
    not_before = datetime.strptime(
        cert["notBefore"], CERT_DATE_FMT
    ).replace(tzinfo=timezone.utc)

    not_after = datetime.strptime(
        cert["notAfter"], CERT_DATE_FMT
    ).replace(tzinfo=timezone.utc)

    return not_before, not_after


def _cert_common_name(name_tuples):
    """Extract commonName from certificate subject/issuer."""
    for rdn in name_tuples:
        for key, value in rdn:
            if key == "commonName":
                return value

    return None


def inspect_host_tls(
    host: str,
    port: int = 443,
    timeout: float = 6.0,
    use_starttls_smtp: bool = False
) -> dict:

    context = ssl.create_default_context()

    # We inspect the certificate even if it is untrusted.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    smtp = None

    try:

        if use_starttls_smtp:

            smtp = smtplib.SMTP(timeout=timeout)

            smtp.connect(host, port)
            smtp.ehlo()

            if not smtp.has_extn("starttls"):
                try:
                    smtp.quit()
                except Exception:
                    pass

                return {
                    "host": host,
                    "port": port,
                    "tls_available": False,
                    "test_result": "UNSUPPORTED",
                    "error": "Server does not advertise STARTTLS support.",
                }

            raw_sock = smtp.sock

            tls_sock = context.wrap_socket(
                raw_sock,
                server_hostname=host
            )

            cert = tls_sock.getpeercert()
            protocol = tls_sock.version()
            cipher = tls_sock.cipher()

            tls_sock.close()

            smtp.sock = None

            try:
                smtp.close()
            except Exception:
                pass

        else:

            with socket.create_connection(
                (host, port),
                timeout=timeout
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=host
                ) as tls_sock:

                    cert = tls_sock.getpeercert()
                    protocol = tls_sock.version()
                    cipher = tls_sock.cipher()

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionRefusedError,
        TimeoutError,
        OSError,
        smtplib.SMTPException
    ) as e:

        if smtp:
            try:
                smtp.close()
            except Exception:
                pass

        return {
            "host": host,
            "port": port,
            "tls_available": False,
            "test_result": "INCONCLUSIVE",
            "error": str(e),
        }

    if not cert:

        return {
            "host": host,
            "port": port,
            "tls_available": True,
            "certificate_available": False,
            "test_result": "SUCCESS",
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "note": (
                "TLS handshake succeeded but certificate metadata "
                "was not returned."
            ),
        }

    not_before, not_after = _parse_cert_dates(cert)

    now = datetime.now(timezone.utc)

    days_remaining = (not_after - now).days

    subject_cn = _cert_common_name(
        cert.get("subject", ())
    )

    issuer_cn = _cert_common_name(
        cert.get("issuer", ())
    )

    san_list = [
        value
        for key, value in cert.get("subjectAltName", ())
        if key == "DNS"
    ]

    hostname_match = (
        host in san_list
        or host == subject_cn
        or any(
            san.startswith("*.") and host.endswith(san[1:])
            for san in san_list
        )
    )

    return {
        "host": host,
        "port": port,
        "tls_available": True,
        "certificate_available": True,
        "test_result": "SUCCESS",
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
    Test mail servers using SMTP STARTTLS.

    Important distinction:

    - Successful TLS negotiation -> evaluate TLS normally.
    - Confirmed old/insecure TLS protocol -> FAIL.
    - Server explicitly doesn't support STARTTLS -> FAIL.
    - Network timeout/refusal -> INCONCLUSIVE.

    A timeout is NOT treated as proof that TLS is insecure.
    """

    if not mx_hosts:

        return {
            "check": "TLS",
            "status": "INCONCLUSIVE",
            "evidence": (
                "Unable to test TLS because no mail servers "
                "were available from MX records."
            ),
            "cert_check": {
                "check": "Certificate",
                "status": "INCONCLUSIVE",
                "evidence": (
                    "Certificate could not be inspected because "
                    "no mail server was available for TLS testing."
                ),
            },
        }

    successful_result = None
    last_result = None

    for host in mx_hosts:

        for port in (25, 587):

            result = inspect_host_tls(
                host,
                port=port,
                use_starttls_smtp=True
            )

            last_result = result

            if result.get("tls_available"):
                successful_result = result
                break

        if successful_result:
            break

    # ---------------------------------------------------------
    # Could not establish TLS
    # ---------------------------------------------------------

    if not successful_result:

        error = (
            last_result.get("error", "unknown error")
            if last_result
            else "no hosts tried"
        )

        test_result = (
            last_result.get("test_result")
            if last_result
            else "INCONCLUSIVE"
        )

        if test_result == "UNSUPPORTED":

            tls_status = "FAIL"

            tls_evidence = (
                "Mail server does not advertise STARTTLS. "
                "TLS could not be negotiated."
            )

        else:

            tls_status = "INCONCLUSIVE"

            tls_evidence = (
                "TLS/STARTTLS could not be verified against the "
                "available mail servers. "
                f"Last connection error: {error}. "
                "This does not prove that TLS is insecure."
            )

        return {
            "check": "TLS",
            "status": tls_status,
            "evidence": tls_evidence,
            "raw": last_result,
            "cert_check": {
                "check": "Certificate",
                "status": (
                    "INCONCLUSIVE"
                    if tls_status == "INCONCLUSIVE"
                    else "FAIL"
                ),
                "evidence": (
                    "Certificate could not be inspected because "
                    "a TLS connection could not be established."
                ),
            },
        }

    # ---------------------------------------------------------
    # TLS successfully negotiated
    # ---------------------------------------------------------

    tls_status = "PASS"

    tls_evidence = (
        f"STARTTLS negotiated with "
        f"{successful_result['host']}:"
        f"{successful_result['port']} "
        f"using {successful_result.get('protocol')}."
    )

    protocol = successful_result.get("protocol")

    if protocol in (
        "TLSv1",
        "TLSv1.1",
        "SSLv3",
        "SSLv2"
    ):

        tls_status = "FAIL"

        tls_evidence += (
            " Outdated/insecure protocol version negotiated."
        )

    elif protocol == "TLSv1.2":

        tls_status = "WARNING"

        tls_evidence += (
            " TLS 1.2 is acceptable, but TLS 1.3 is recommended."
        )

    # ---------------------------------------------------------
    # Certificate
    # ---------------------------------------------------------

    if not successful_result.get("certificate_available"):

        cert_check = {
            "check": "Certificate",
            "status": "INCONCLUSIVE",
            "evidence": (
                "TLS handshake succeeded but certificate metadata "
                "could not be retrieved."
            ),
        }

    else:

        if successful_result.get("expired"):

            cert_status = "FAIL"

            cert_evidence = (
                f"Certificate for "
                f"{successful_result['host']} "
                f"EXPIRED on "
                f"{successful_result['not_after']}."
            )

        elif successful_result.get("days_remaining", 999) < 14:

            cert_status = "WARNING"

            cert_evidence = (
                f"Certificate expires soon "
                f"({successful_result['days_remaining']} "
                f"days remaining)."
            )

        elif not successful_result.get("hostname_match"):

            cert_status = "WARNING"

            cert_evidence = (
                f"Certificate does not clearly match hostname "
                f"{successful_result['host']}."
            )

        else:

            cert_status = "PASS"

            cert_evidence = (
                f"Valid certificate for "
                f"{successful_result['host']} "
                f"issued by "
                f"{successful_result.get('issuer')}, "
                f"expiring "
                f"{successful_result['not_after']} "
                f"({successful_result['days_remaining']} "
                f"days remaining)."
            )

        cert_check = {
            "check": "Certificate",
            "status": cert_status,
            "evidence": cert_evidence,
            "issuer": successful_result.get("issuer"),
            "subject": successful_result.get("subject"),
            "not_after": successful_result.get("not_after"),
            "hostname_match": successful_result.get("hostname_match"),
        }

    return {
        "check": "TLS",
        "status": tls_status,
        "evidence": tls_evidence,
        "raw": successful_result,
        "cert_check": cert_check,
    }