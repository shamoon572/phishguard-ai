"""
PhishGuard AI — backend API

    Real-Time Phishing URL Detection Platform

Endpoints:
    GET  /api/health          liveness check
    POST /api/scan            run the full detection pipeline on a URL
    GET  /api/history         recent scans performed by this server instance
    GET  /api/history/<id>    fetch a single stored scan (for PDF/JSON export)

All checks are real: SSL handshake, WHOIS RDAP/whois protocol, DNS
resolution, HTTP redirect following, VirusTotal, Google Safe Browsing,
PhishTank, OpenPhish, and a rule-based heuristic engine. No random or
fabricated values are ever returned.
"""

import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from flask_cors import CORS

from config import Config
from services.dns_check import check_dns
from services.heuristics import analyze_heuristics
from services.openphish import check_openphish
from services.phishtank import check_phishtank
from services.redirect_check import check_redirects
from services.risk_engine import compute_risk
from services.safe_browsing import check_safe_browsing
from services.ssl_check import check_ssl
from services.virustotal import check_virustotal
from services.whois_check import check_whois
from utils.rate_limiter import limiter
from utils.validators import URLValidationError, normalize_and_validate

app = Flask(__name__)
app.config.from_object(Config)

CORS(app, origins=Config.ALLOWED_ORIGINS, supports_credentials=False)
limiter.init_app(app)

# In-memory scan history for this process. Swap for a real database
# (Postgres/SQLite) before deploying beyond a single demo instance.
_history: dict[str, dict] = {}
_history_order: list[str] = []
MAX_HISTORY = 200


def _run_checks(url: str, hostname: str) -> dict:
    """Run every check concurrently and collect results by name."""
    jobs = {
        "ssl": lambda: check_ssl(url, timeout=Config.REQUEST_TIMEOUT_SECONDS),
        "whois": lambda: check_whois(hostname),
        "dns": lambda: check_dns(hostname, timeout=Config.REQUEST_TIMEOUT_SECONDS),
        "redirects": lambda: check_redirects(url, max_redirects=Config.MAX_REDIRECTS, timeout=Config.REQUEST_TIMEOUT_SECONDS),
        "virustotal": lambda: check_virustotal(url, Config.VIRUSTOTAL_API_KEY, timeout=Config.REQUEST_TIMEOUT_SECONDS + 2),
        "safe_browsing": lambda: check_safe_browsing(url, Config.GOOGLE_SAFE_BROWSING_API_KEY, timeout=Config.REQUEST_TIMEOUT_SECONDS),
        "phishtank": lambda: check_phishtank(url, Config.PHISHTANK_API_KEY, timeout=Config.REQUEST_TIMEOUT_SECONDS, ttl=Config.PHISHTANK_CACHE_TTL_SECONDS),
        "openphish": lambda: check_openphish(url, hostname, Config.OPENPHISH_FEED_URL, ttl=Config.OPENPHISH_CACHE_TTL_SECONDS, timeout=Config.REQUEST_TIMEOUT_SECONDS + 2),
        "heuristics": lambda: analyze_heuristics(url, timeout=Config.REQUEST_TIMEOUT_SECONDS),
    }

    results = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        future_map = {pool.submit(fn): name for name, fn in jobs.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception as exc:  # a single check failing must not take down the whole scan
                results[name] = {"status": "unavailable", "message": f"Check failed: {exc}"}
    return results


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "PhishGuard AI", "version": "1.0.0"})


@app.route("/api/scan", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_SCAN)
def scan():
    body = request.get_json(silent=True) or {}
    raw_url = body.get("url", "")

    try:
        clean_url = normalize_and_validate(raw_url)
    except URLValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    hostname = urlparse(clean_url).hostname
    started = time.time()

    results = _run_checks(clean_url, hostname)
    risk = compute_risk(results)

    scan_id = str(uuid.uuid4())
    record = {
        "id": scan_id,
        "url": clean_url,
        "hostname": hostname,
        "timestamp": time.time(),
        "duration_ms": round((time.time() - started) * 1000),
        "checks": results,
        "risk": risk,
    }

    _history[scan_id] = record
    _history_order.append(scan_id)
    if len(_history_order) > MAX_HISTORY:
        oldest = _history_order.pop(0)
        _history.pop(oldest, None)

    return jsonify(record)


@app.route("/api/history", methods=["GET"])
@limiter.limit(Config.RATE_LIMIT_DEFAULT)
def history():
    search = request.args.get("q", "").lower()
    items = [_history[sid] for sid in reversed(_history_order)]
    if search:
        items = [r for r in items if search in r["url"].lower()]

    summaries = [
        {
            "id": r["id"],
            "url": r["url"],
            "timestamp": r["timestamp"],
            "score": r["risk"]["score"],
            "verdict": r["risk"]["verdict"]["label"],
        }
        for r in items
    ]
    return jsonify({"count": len(summaries), "results": summaries})


@app.route("/api/history/<scan_id>", methods=["GET"])
@limiter.limit(Config.RATE_LIMIT_DEFAULT)
def history_detail(scan_id):
    record = _history.get(scan_id)
    if not record:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify(record)


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests. Please slow down and try again shortly."}), 429


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)
