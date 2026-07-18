"""
Risk scoring engine.

Combines every individual check into a single 0-100 risk score and a
three-tier verdict (safe / suspicious / phishing), plus a plain-language
"AI verdict" explanation built directly from the same findings — no
random numbers, every point on the score traces back to a concrete signal.
"""

# Each check contributes points based on its own status. Weights reflect how
# strong a phishing signal that particular check is in practice.
WEIGHTS = {
    "ssl": {"safe": 0, "warning": 8, "danger": 18, "unavailable": 3},
    "whois": {"safe": 0, "warning": 10, "danger": 20, "unavailable": 3},
    "dns": {"safe": 0, "warning": 6, "danger": 15, "unavailable": 3},
    "redirects": {"safe": 0, "warning": 8, "danger": 15, "unavailable": 2},
    "virustotal": {"safe": 0, "warning": 12, "danger": 25, "unavailable": 0},
    "safe_browsing": {"safe": 0, "warning": 10, "danger": 25, "unavailable": 0},
    "phishtank": {"safe": 0, "warning": 10, "danger": 20, "unavailable": 0},
    "openphish": {"safe": 0, "warning": 8, "danger": 18, "unavailable": 0},
    "heuristics": {"safe": 0, "warning": 10, "danger": 22, "unavailable": 0},
}

REASON_TEXT = {
    "uses_ip": "Uses an IP address instead of a domain name",
    "new_domain": "Recently registered domain",
    "brand_keyword": "Suspicious brand/banking keywords in the URL",
    "many_redirects": "Multiple redirects before reaching the final page",
    "fake_login": "Hidden or suspicious login form detected",
    "known_phish_host": "Matches a known phishing host in threat feeds",
    "suspicious_tld": "Suspicious or high-abuse top-level domain",
    "executable": "Links directly to an executable/script download",
    "bad_ssl": "Invalid, expired, or self-signed TLS certificate",
    "homograph": "Look-alike (homograph) characters in the domain",
    "typosquat": "Domain closely mimics a well-known brand",
}


def _verdict_from_score(score: int) -> dict:
    if score >= 70:
        return {"label": "Phishing", "tier": "danger", "emoji": "🔴"}
    if score >= 35:
        return {"label": "Suspicious", "tier": "warning", "emoji": "🟡"}
    return {"label": "Safe", "tier": "safe", "emoji": "🟢"}


def compute_risk(results: dict) -> dict:
    """
    results: dict keyed by check name -> that check's result dict (must include "status")
    Returns: {"score": int, "verdict": {...}, "reasons": [...], "recommendation": str}
    """
    score = 0
    reasons = []

    for check_name, weight_table in WEIGHTS.items():
        result = results.get(check_name)
        if not result:
            continue
        status = result.get("status", "unavailable")
        score += weight_table.get(status, 0)

    score = max(0, min(100, score))

    # Build human-readable reasons directly from what each check actually found
    heur = results.get("heuristics", {})
    if heur.get("uses_ip"):
        reasons.append(REASON_TEXT["uses_ip"])
    if heur.get("fake_login_detected"):
        reasons.append(REASON_TEXT["fake_login"])
    for finding in heur.get("findings", []):
        signal = finding["signal"]
        if "TLD" in signal:
            reasons.append(REASON_TEXT["suspicious_tld"])
        elif "homograph" in signal.lower():
            reasons.append(REASON_TEXT["homograph"])
        elif "typosquat" in signal.lower():
            reasons.append(REASON_TEXT["typosquat"])
        elif "executable" in signal.lower():
            reasons.append(REASON_TEXT["executable"])
        elif "keyword" in signal.lower() or "brand" in signal.lower():
            reasons.append(REASON_TEXT["brand_keyword"])

    whois_result = results.get("whois", {})
    if whois_result.get("status") in ("danger", "warning") and whois_result.get("available"):
        reasons.append(REASON_TEXT["new_domain"])

    redirects = results.get("redirects", {})
    if redirects.get("redirect_count", 0) >= 3:
        reasons.append(REASON_TEXT["many_redirects"])

    ssl_result = results.get("ssl", {})
    if ssl_result.get("status") == "danger":
        reasons.append(REASON_TEXT["bad_ssl"])

    for feed_name in ("phishtank", "openphish", "virustotal", "safe_browsing"):
        feed_result = results.get(feed_name, {})
        if feed_result.get("status") == "danger":
            reasons.append(REASON_TEXT["known_phish_host"])
            break

    # De-duplicate while preserving order
    seen = set()
    unique_reasons = []
    for r in reasons:
        if r not in seen:
            unique_reasons.append(r)
            seen.add(r)

    verdict = _verdict_from_score(score)

    if verdict["tier"] == "danger":
        recommendation = "Do not enter credentials, payment details, or personal information on this site. Close the tab and report it if received via email or message."
    elif verdict["tier"] == "warning":
        recommendation = "Proceed with caution. Verify the domain independently before entering any sensitive information."
    else:
        recommendation = "No major threats detected. Standard browsing precautions still apply."

    return {
        "score": score,
        "verdict": verdict,
        "reasons": unique_reasons if unique_reasons else ["No significant risk indicators found."],
        "recommendation": recommendation,
    }
