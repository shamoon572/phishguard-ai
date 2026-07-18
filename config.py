"""
PhishGuard AI — configuration
All secrets are read from environment variables. Never hard-code API keys.
Copy .env.example to .env and fill in your own keys before running the app.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # --- Flask ---
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    ENV = os.getenv("FLASK_ENV", "production")

    # --- CORS ---
    ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500").split(",")

    # --- External API keys (all optional — features degrade gracefully if absent) ---
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")  # PhishTank works without a key at low volume

    # --- Feed refresh / caching ---
    OPENPHISH_FEED_URL = os.getenv("OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
    OPENPHISH_CACHE_TTL_SECONDS = int(os.getenv("OPENPHISH_CACHE_TTL_SECONDS", "3600"))
    PHISHTANK_CACHE_TTL_SECONDS = int(os.getenv("PHISHTANK_CACHE_TTL_SECONDS", "3600"))

    # --- Network timeouts ---
    REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "6"))

    # --- Rate limiting ---
    RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "30 per minute")
    RATE_LIMIT_SCAN = os.getenv("RATE_LIMIT_SCAN", "10 per minute")

    # --- Redirect chain safety ---
    MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "8"))
