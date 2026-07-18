"""
Input validation & sanitization.

Every URL submitted by a client passes through here before any downstream
service (WHOIS, DNS, sockets, subprocess-free requests) touches it. This
module is the single choke point for:
  - basic well-formedness checks
  - blocking private / loopback / link-local / cloud-metadata targets (SSRF)
  - stripping characters that have no business in a URL a user "scans"
  - a hard length cap
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048

# Only allow http/https schemes — file://, ftp://, gopher://, data:// etc. are rejected
ALLOWED_SCHEMES = {"http", "https"}

# Characters that should never appear in a legitimate URL we forward to
# shell-free HTTP libraries, but which show up in injection attempts.
_DANGEROUS_CHARS = re.compile(r"[\x00-\x1f\x7f;`$|&<>\"'\\]")

_METADATA_HOSTS = {
    "169.254.169.254",  # AWS/GCP/Azure metadata endpoint
    "metadata.google.internal",
}


class URLValidationError(ValueError):
    """Raised when a submitted URL fails validation."""


def sanitize_input(raw: str) -> str:
    """Trim, cap length, and reject control / shell-metacharacters."""
    if raw is None:
        raise URLValidationError("URL is required.")

    candidate = raw.strip()

    if not candidate:
        raise URLValidationError("URL is required.")

    if len(candidate) > MAX_URL_LENGTH:
        raise URLValidationError("URL is too long.")

    if _DANGEROUS_CHARS.search(candidate):
        raise URLValidationError("URL contains disallowed characters.")

    return candidate


def _is_private_or_reserved(host: str) -> bool:
    """Best-effort SSRF guard: resolve the host and reject internal ranges."""
    if host in _METADATA_HOSTS:
        return True

    try:
        # Host might already be a literal IP
        ip_obj = ipaddress.ip_address(host)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
        )
    except ValueError:
        pass

    # Resolve hostname and check every returned address
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Can't resolve — let downstream DNS check surface this clearly instead
        return False

    for info in infos:
        addr = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
        ):
            return True
    return False


def normalize_and_validate(raw_url: str) -> str:
    """
    Full pipeline: sanitize characters, enforce scheme allow-list, ensure a
    host is present, and block requests aimed at internal/private network
    ranges. Returns the normalized URL (default scheme added if missing) or
    raises URLValidationError with a user-safe message.
    """
    candidate = sanitize_input(raw_url)

    # Default to https:// if no scheme was supplied, mirroring how a user types URLs
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise URLValidationError("Only http:// and https:// URLs are supported.")

    if not parsed.hostname:
        raise URLValidationError("URL must include a valid domain or host.")

    if _is_private_or_reserved(parsed.hostname):
        raise URLValidationError("Scanning internal or private network addresses is not permitted.")

    return parsed.geturl()


def escape_for_display(text: str) -> str:
    """Escape a value before it is ever echoed back in JSON/HTML contexts."""
    if text is None:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
