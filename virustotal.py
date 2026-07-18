"""
VirusTotal integration (API v3).

Submits/looks up the URL and returns the vendor detection summary.
Requires VIRUSTOTAL_API_KEY. If absent, the check is reported as
unavailable rather than faked — the frontend renders this distinctly
from an actual "safe" verdict.
"""

import base64

import requests

API_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_virustotal(url: str, api_key: str, timeout: int = 8) -> dict:
    if not api_key:
        return {
            "status": "unavailable",
            "message": "VirusTotal API key not configured.",
        }

    headers = {"x-apikey": api_key}

    try:
        lookup = requests.get(f"{API_BASE}/urls/{_url_id(url)}", headers=headers, timeout=timeout)

        if lookup.status_code == 404:
            # Not previously scanned — submit it, then report "pending"
            submit = requests.post(
                f"{API_BASE}/urls", headers=headers, data={"url": url}, timeout=timeout
            )
            if submit.status_code not in (200, 201):
                return {"status": "unavailable", "message": "VirusTotal submission failed."}
            return {
                "status": "warning",
                "message": "URL submitted to VirusTotal for first-time analysis; results not yet available.",
                "pending": True,
            }

        if lookup.status_code != 200:
            return {"status": "unavailable", "message": f"VirusTotal returned HTTP {lookup.status_code}."}

        data = lookup.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious >= 3:
            status = "danger"
        elif malicious > 0 or suspicious > 0:
            status = "warning"
        else:
            status = "safe"

        return {
            "status": status,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total,
            "message": f"{malicious}/{total} security vendors flagged this URL as malicious.",
        }

    except requests.exceptions.RequestException as exc:
        return {"status": "unavailable", "message": f"VirusTotal request failed: {exc}"}
