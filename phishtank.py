"""
PhishTank integration.

PhishTank exposes a "checkurl" endpoint that answers whether a specific URL
is a confirmed phish in their community-curated database. Works without an
API key at low request volume; supplying PHISHTANK_API_KEY raises limits.
"""

import time

import requests

API_URL = "https://checkurl.phishtank.com/checkurl/"

# Simple per-URL response cache to avoid hammering PhishTank on repeat scans
_cache: dict[str, tuple[float, dict]] = {}


def check_phishtank(url: str, api_key: str = "", timeout: int = 6, ttl: int = 3600) -> dict:
    cached = _cache.get(url)
    if cached and (time.time() - cached[0]) < ttl:
        return cached[1]

    data = {"url": url, "format": "json"}
    if api_key:
        data["app_key"] = api_key

    try:
        resp = requests.post(
            API_URL, data=data, timeout=timeout, headers={"User-Agent": "PhishGuardAI/1.0"}
        )
        if resp.status_code != 200:
            return {"status": "unavailable", "message": f"PhishTank returned HTTP {resp.status_code}."}

        payload = resp.json().get("results", {})
        in_database = payload.get("in_database", False)
        is_valid_phish = payload.get("valid", False) if in_database else False

        if in_database and is_valid_phish:
            result = {
                "status": "danger",
                "listed": True,
                "message": "Confirmed phishing URL in the PhishTank database.",
            }
        elif in_database:
            result = {
                "status": "warning",
                "listed": True,
                "message": "URL is submitted to PhishTank but not yet verified.",
            }
        else:
            result = {
                "status": "safe",
                "listed": False,
                "message": "Not found in the PhishTank database.",
            }

        _cache[url] = (time.time(), result)
        return result

    except requests.exceptions.RequestException as exc:
        return {"status": "unavailable", "message": f"PhishTank request failed: {exc}"}
