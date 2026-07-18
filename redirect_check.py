"""
Redirect chain inspection.

Phishing pages frequently hide behind a chain of redirects (URL shorteners,
tracking links, open redirects on legitimate domains) to dodge blocklists
and obscure the final destination. We follow the chain ourselves (bounded)
rather than trusting a single hop.
"""

from urllib.parse import urlparse

import requests

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id",
}


def check_redirects(url: str, max_redirects: int = 8, timeout: int = 6) -> dict:
    chain = [url]
    current = url
    is_shortener = urlparse(url).hostname in SHORTENER_DOMAINS

    try:
        session = requests.Session()
        session.max_redirects = max_redirects
        resp = session.head(current, allow_redirects=True, timeout=timeout, headers={"User-Agent": "PhishGuardAI/1.0"})
        for r in resp.history:
            chain.append(r.headers.get("Location", r.url))
        final_url = resp.url
        if final_url not in chain:
            chain.append(final_url)
        redirect_count = len(resp.history)
    except requests.exceptions.TooManyRedirects:
        return {
            "status": "danger",
            "redirect_count": max_redirects,
            "chain": chain,
            "is_shortener": is_shortener,
            "message": f"Exceeded {max_redirects} redirects — likely obfuscation.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "status": "warning",
            "redirect_count": 0,
            "chain": chain,
            "is_shortener": is_shortener,
            "message": f"Could not follow redirects: {exc}",
        }

    if redirect_count == 0:
        status = "safe"
    elif redirect_count <= 2 and not is_shortener:
        status = "safe"
    elif redirect_count <= 4 or is_shortener:
        status = "warning"
    else:
        status = "danger"

    return {
        "status": status,
        "redirect_count": redirect_count,
        "chain": chain,
        "final_url": final_url,
        "is_shortener": is_shortener,
        "message": f"{redirect_count} redirect(s) detected." + (" Uses a URL shortener." if is_shortener else ""),
    }
