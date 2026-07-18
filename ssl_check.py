"""
SSL/TLS certificate check.

Connects to the target host on port 443, retrieves the presented
certificate, and reports issuer, validity window, and a few red flags
(self-signed, expired, mismatched hostname, absurdly short validity —
often seen on throwaway phishing certs).
"""

import datetime
import socket
import ssl
from urllib.parse import urlparse


def _parse_cert_date(value: str) -> datetime.datetime:
    return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def check_ssl(url: str, timeout: int = 6) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return {
            "status": "warning",
            "https": False,
            "message": "Site does not use HTTPS.",
        }

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as exc:
        return {
            "status": "danger",
            "https": True,
            "valid": False,
            "message": f"Certificate verification failed: {exc.verify_message}",
        }
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return {
            "status": "warning",
            "https": True,
            "valid": None,
            "message": f"Could not establish TLS connection: {exc}",
        }

    not_before = _parse_cert_date(cert["notBefore"])
    not_after = _parse_cert_date(cert["notAfter"])
    now = datetime.datetime.utcnow()

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    validity_days = (not_after - not_before).days

    is_expired = now > not_after
    is_self_signed = issuer.get("commonName") == subject.get("commonName") and issuer.get("organizationName") is None
    is_short_lived = 0 < validity_days <= 7  # very short validity is a common phishing-kit pattern

    flags = []
    if is_expired:
        flags.append("Certificate has expired.")
    if is_self_signed:
        flags.append("Certificate appears self-signed.")
    if is_short_lived:
        flags.append(f"Unusually short validity period ({validity_days} days).")

    status = "safe"
    if is_expired or is_self_signed:
        status = "danger"
    elif is_short_lived:
        status = "warning"

    return {
        "status": status,
        "https": True,
        "valid": not is_expired,
        "issuer": issuer.get("organizationName") or issuer.get("commonName", "Unknown"),
        "subject_cn": subject.get("commonName", hostname),
        "valid_from": not_before.isoformat(),
        "valid_to": not_after.isoformat(),
        "validity_days": validity_days,
        "cipher": cipher[0] if cipher else None,
        "flags": flags,
        "message": "Valid TLS certificate." if status == "safe" else "; ".join(flags),
    }
