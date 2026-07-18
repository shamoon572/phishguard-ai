"""
Google Safe Browsing v4 integration.

Checks the URL against Google's threat lists (malware, social engineering,
unwanted software, potentially harmful applications). Requires
GOOGLE_SAFE_BROWSING_API_KEY.
"""

import requests

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_safe_browsing(url: str, api_key: str, timeout: int = 6) -> dict:
    if not api_key:
        return {
            "status": "unavailable",
            "message": "Google Safe Browsing API key not configured.",
        }

    payload = {
        "client": {"clientId": "phishguard-ai", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(API_URL, params={"key": api_key}, json=payload, timeout=timeout)
        if resp.status_code != 200:
            return {"status": "unavailable", "message": f"Safe Browsing returned HTTP {resp.status_code}."}

        matches = resp.json().get("matches", [])
        if matches:
            threat_types = sorted({m["threatType"] for m in matches})
            return {
                "status": "danger",
                "flagged": True,
                "threat_types": threat_types,
                "message": f"Flagged by Google Safe Browsing: {', '.join(threat_types)}.",
            }

        return {
            "status": "safe",
            "flagged": False,
            "message": "Not found on Google Safe Browsing threat lists.",
        }

    except requests.exceptions.RequestException as exc:
        return {"status": "unavailable", "message": f"Safe Browsing request failed: {exc}"}
