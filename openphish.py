"""
OpenPhish integration.

OpenPhish publishes a free plaintext feed of currently active phishing URLs.
We cache the feed in memory (refreshed on a TTL) and match the submitted URL
and its hostname against it rather than re-downloading on every scan.
"""

import time

import requests

_feed_cache: dict = {"fetched_at": 0.0, "urls": set(), "hosts": set()}


def _refresh_feed(feed_url: str, ttl: int, timeout: int) -> None:
    now = time.time()
    if _feed_cache["urls"] and (now - _feed_cache["fetched_at"]) < ttl:
        return

    try:
        resp = requests.get(feed_url, timeout=timeout)
        if resp.status_code == 200:
            lines = [line.strip() for line in resp.text.splitlines() if line.strip()]
            _feed_cache["urls"] = set(lines)
            _feed_cache["fetched_at"] = now
    except requests.exceptions.RequestException:
        # Keep serving the stale cache (if any) rather than failing the whole scan
        pass


def check_openphish(url: str, hostname: str, feed_url: str, ttl: int = 3600, timeout: int = 8) -> dict:
    _refresh_feed(feed_url, ttl, timeout)

    if not _feed_cache["urls"]:
        return {
            "status": "unavailable",
            "message": "OpenPhish feed could not be retrieved.",
        }

    exact_match = url in _feed_cache["urls"]
    host_match = any(hostname in entry for entry in _feed_cache["urls"]) if not exact_match else False

    if exact_match:
        return {"status": "danger", "listed": True, "message": "Exact URL match in the OpenPhish feed."}
    if host_match:
        return {
            "status": "warning",
            "listed": True,
            "message": "Domain appears elsewhere in the OpenPhish feed.",
        }
    return {"status": "safe", "listed": False, "message": "Not found in the OpenPhish feed."}
