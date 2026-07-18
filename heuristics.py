"""
Heuristic engine.

Everything here is a rule-based signal derived directly from the URL string
and, where reachable, the page's HTML — no ML black box, no invented scores.
Each function returns a small, explainable finding that feeds the AI
verdict and the overall risk score.
"""

import ipaddress
import re
from urllib.parse import urlparse

import requests
import tldextract

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "ga", "work", "loan", "men", "date",
}

BRAND_KEYWORDS = [
    "paypal", "netflix", "amazon", "apple", "microsoft", "google", "facebook", "instagram",
    "bank", "chase", "wellsfargo", "hsbc", "irs", "gov", "coinbase", "binance", "outlook",
    "office365", "icloud", "whatsapp", "steam", "verify", "secure", "login", "signin", "account",
]

FAKE_LOGIN_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "confirm", "password", "security", "unlock",
]

EXECUTABLE_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".jar", ".ps1", ".vbs")

# Cyrillic/Greek characters commonly used to spoof Latin look-alikes (a very small
# illustrative subset — a full confusables table is out of scope here)
HOMOGRAPH_RANGES = [
    (0x0400, 0x04FF),  # Cyrillic
    (0x0370, 0x03FF),  # Greek
]

POPULAR_DOMAINS = [
    "paypal.com", "netflix.com", "amazon.com", "apple.com", "microsoft.com", "google.com",
    "facebook.com", "instagram.com", "chase.com", "wellsfargo.com", "coinbase.com", "binance.com",
]


def _has_homograph_chars(text: str) -> bool:
    for ch in text:
        code = ord(ch)
        if any(lo <= code <= hi for lo, hi in HOMOGRAPH_RANGES):
            return True
    return False


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = curr
    return prev[-1]


def _check_typosquatting(domain: str) -> str | None:
    for popular in POPULAR_DOMAINS:
        distance = _levenshtein(domain, popular)
        if 0 < distance <= 2:
            return popular
    return None


def analyze_heuristics(url: str, timeout: int = 6) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    extracted = tldextract.extract(url)
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    subdomain_count = len([p for p in extracted.subdomain.split(".") if p]) if extracted.subdomain else 0

    findings = []  # list of {"signal": str, "severity": "low"|"medium"|"high"}

    # 1. Raw IP address instead of a domain name
    try:
        ipaddress.ip_address(hostname)
        findings.append({"signal": "URL uses a raw IP address instead of a domain name.", "severity": "high"})
        uses_ip = True
    except ValueError:
        uses_ip = False

    # 2. Suspicious / cheap TLD frequently abused for phishing
    suspicious_tld = extracted.suffix.split(".")[-1] if extracted.suffix else ""
    if suspicious_tld in SUSPICIOUS_TLDS:
        findings.append({"signal": f"Uses a TLD frequently abused for abuse/phishing (.{suspicious_tld}).", "severity": "medium"})

    # 3. Homograph / Unicode attack in hostname
    if _has_homograph_chars(hostname) or hostname.startswith("xn--") or ".xn--" in hostname:
        findings.append({"signal": "Hostname contains non-Latin look-alike (homograph) characters.", "severity": "high"})

    # 4. Typosquatting against well-known brands
    typo_target = _check_typosquatting(registered_domain)
    if typo_target:
        findings.append({"signal": f"Domain closely resembles '{typo_target}' (possible typosquatting).", "severity": "high"})

    # 5. Brand keyword stuffed into a non-brand domain
    lowered_host = hostname.lower()
    if registered_domain not in POPULAR_DOMAINS:
        for brand in BRAND_KEYWORDS:
            if brand in lowered_host and brand not in registered_domain:
                findings.append({"signal": f"Brand keyword '{brand}' used in an unrelated domain.", "severity": "high"})
                break

    # 6. Suspicious keywords anywhere in the full URL (path/query too)
    full_lower = url.lower()
    matched_keywords = [k for k in FAKE_LOGIN_KEYWORDS if k in full_lower]
    if len(matched_keywords) >= 2:
        findings.append({
            "signal": f"Multiple credential-harvesting keywords present ({', '.join(matched_keywords)}).",
            "severity": "medium",
        })

    # 7. Excessive subdomain count (e.g. paypal.com.verify.security.example.ru)
    if subdomain_count >= 3:
        findings.append({"signal": f"Unusually high subdomain count ({subdomain_count}).", "severity": "medium"})

    # 8. Executable / risky file extension in the path
    if any(full_lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
        findings.append({"signal": "URL points directly to an executable/script download.", "severity": "high"})

    # 9. @ symbol in URL (classic obfuscation: real host hidden after '@')
    if "@" in url:
        findings.append({"signal": "URL contains an '@' character, often used to mask the real destination.", "severity": "high"})

    # 10. Hyphen-heavy domain (another classic phishing lexical pattern)
    if extracted.domain.count("-") >= 3:
        findings.append({"signal": "Domain name contains an unusually high number of hyphens.", "severity": "low"})

    # 11. Best-effort fake login form detection via a lightweight fetch
    fake_login_detected = False
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "PhishGuardAI/1.0"})
        html = resp.text.lower()
        has_password_field = 'type="password"' in html or "type='password'" in html
        mentions_brand_not_owned = any(
            brand in html for brand in BRAND_KEYWORDS if brand not in registered_domain
        )
        if has_password_field and mentions_brand_not_owned:
            fake_login_detected = True
            findings.append({
                "signal": "Page presents a login form while referencing a brand it does not belong to.",
                "severity": "high",
            })
        elif has_password_field and (suspicious_tld in SUSPICIOUS_TLDS or uses_ip):
            fake_login_detected = True
            findings.append({"signal": "Login form hosted on high-risk infrastructure.", "severity": "medium"})
    except requests.exceptions.RequestException:
        pass  # page unreachable — heuristics based purely on the URL string still apply

    severity_rank = {"low": 1, "medium": 2, "high": 3}
    high_count = sum(1 for f in findings if f["severity"] == "high")
    medium_count = sum(1 for f in findings if f["severity"] == "medium")

    if high_count >= 1:
        status = "danger"
    elif medium_count >= 2:
        status = "warning"
    elif findings:
        status = "warning"
    else:
        status = "safe"

    return {
        "status": status,
        "registered_domain": registered_domain,
        "subdomain_count": subdomain_count,
        "uses_ip": uses_ip,
        "fake_login_detected": fake_login_detected,
        "findings": sorted(findings, key=lambda f: -severity_rank[f["severity"]]),
        "message": f"{len(findings)} heuristic signal(s) detected." if findings else "No heuristic red flags detected.",
    }
