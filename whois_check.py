"""
WHOIS lookup.

Domain age is one of the strongest phishing signals: attackers overwhelmingly
register a fresh domain right before a campaign. We surface age, registrar,
and creation/expiry dates, and flag anything younger than 30 days.
"""

import datetime

import whois as pywhois

NEW_DOMAIN_THRESHOLD_DAYS = 30
YOUNG_DOMAIN_THRESHOLD_DAYS = 180


def _first(value):
    """python-whois sometimes returns a list for a field; normalize to a single value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def check_whois(hostname: str) -> dict:
    try:
        record = pywhois.whois(hostname)
    except Exception as exc:  # library raises varied, loosely-typed errors per-TLD
        return {
            "status": "warning",
            "available": False,
            "message": f"WHOIS lookup unavailable: {exc}",
        }

    creation_date = _first(record.creation_date)
    expiration_date = _first(record.expiration_date)
    registrar = _first(record.registrar)

    if not creation_date:
        return {
            "status": "warning",
            "available": False,
            "message": "Registrar did not return a creation date (common for privacy-protected or ccTLD domains).",
        }

    if isinstance(creation_date, str):
        # Fallback parse if the library couldn't coerce it
        try:
            creation_date = datetime.datetime.fromisoformat(creation_date)
        except ValueError:
            return {"status": "warning", "available": False, "message": "Could not parse creation date."}

    now = datetime.datetime.utcnow()
    age_days = (now - creation_date.replace(tzinfo=None)).days

    if age_days < NEW_DOMAIN_THRESHOLD_DAYS:
        status = "danger"
        message = f"Domain registered only {age_days} day(s) ago — high-risk indicator."
    elif age_days < YOUNG_DOMAIN_THRESHOLD_DAYS:
        status = "warning"
        message = f"Domain is relatively new ({age_days} days old)."
    else:
        status = "safe"
        message = f"Domain age: {age_days} days."

    return {
        "status": status,
        "available": True,
        "registrar": registrar or "Unknown",
        "created": creation_date.isoformat(),
        "expires": expiration_date.isoformat() if hasattr(expiration_date, "isoformat") else expiration_date,
        "age_days": age_days,
        "message": message,
    }
