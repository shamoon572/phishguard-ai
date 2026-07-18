# PhishGuard AI

Real-time AI-powered phishing URL detection platform. A Flask backend runs
real SSL, WHOIS, DNS, redirect, threat-intel (VirusTotal, Google Safe
Browsing, PhishTank, OpenPhish) and heuristic checks against a submitted URL;
a dark, glassmorphic dashboard frontend visualizes the results with a risk
gauge, detection report, AI-style explanation, and scan history.

```
phishguard-ai/
├── backend/
│   ├── app.py                 Flask app & REST API (/api/scan, /api/history)
│   ├── config.py               Env-driven configuration
│   ├── requirements.txt
│   ├── .env.example
│   ├── services/
│   │   ├── ssl_check.py        TLS certificate inspection
│   │   ├── whois_check.py      Domain age / registrar lookup
│   │   ├── dns_check.py        A/AAAA/NS/MX resolution
│   │   ├── redirect_check.py   Redirect chain + shortener detection
│   │   ├── virustotal.py       VirusTotal v3 API
│   │   ├── safe_browsing.py    Google Safe Browsing v4 API
│   │   ├── phishtank.py        PhishTank checkurl API
│   │   ├── openphish.py        OpenPhish feed matching
│   │   ├── heuristics.py       Rule-based lexical/content signals
│   │   └── risk_engine.py      Aggregates checks into score + verdict
│   └── utils/
│       ├── validators.py       URL sanitization & SSRF guard
│       └── rate_limiter.py     flask-limiter setup
└── frontend/
    ├── index.html
    ├── css/style.css
    └── js/
        ├── scan.js             Scan lifecycle + result rendering
        ├── charts.js           Risk gauge + Chart.js timeline
        └── app.js              Nav, history table, PDF/JSON/copy export
```

## 1. Backend setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and add whichever API keys you have. Every key is optional —
if a key is missing, that specific check reports "unavailable" instead of a
fabricated result. No check ever returns a random or fake value.

| Service | Get a key |
|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| Google Safe Browsing | https://developers.google.com/safe-browsing/v4/get-started |
| PhishTank | https://www.phishtank.com/api_register.php (optional — works unauthenticated at low volume) |

Run the API:

```bash
python app.py
# or, in production:
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

The API listens on `http://localhost:5000`.

## 2. Frontend setup

The frontend is static HTML/CSS/JS — no build step. Serve it with any static
server, e.g.:

```bash
cd frontend
python3 -m http.server 5500
```

Open `http://localhost:5500`. If your backend runs somewhere other than
`http://localhost:5000`, set it before the page scripts load:

```html
<script>window.PHISHGUARD_API_BASE = "https://your-api.example.com";</script>
```

Update `ALLOWED_ORIGINS` in `backend/.env` to match your frontend's origin.

## 3. Security notes

- All submitted URLs pass through `utils/validators.py`, which strips
  shell/control characters, restricts schemes to `http`/`https`, and blocks
  requests aimed at private, loopback, link-local, and cloud metadata
  addresses (SSRF protection).
- No `subprocess`/shell calls are made anywhere in the checks — every
  network operation uses `requests`, `socket`, `ssl`, `dns.resolver`, or the
  `whois` library directly, so there is no command-injection surface.
- `/api/scan` is rate-limited (`RATE_LIMIT_SCAN`, default 10/minute/IP).
- CORS is restricted to `ALLOWED_ORIGINS`.
- Scan history is stored in memory for the life of the process — swap in a
  real database before running this beyond a single-instance demo.

## 4. What "real detection" means here

Every check in `backend/services/` performs an actual network operation or
rule evaluation against the submitted URL — nothing is randomized. Checks
that depend on a third-party API key (VirusTotal, Safe Browsing) return a
`status: "unavailable"` result with an explanatory message when no key is
configured, so the frontend can render that distinctly from a genuine "safe"
verdict rather than silently pretending the check ran.
