try:
    import requests
except ImportError:
    requests = None
from urllib.parse import urlparse
from ..config import settings

def check_virustotal(url: str):
    if requests is None:
        return {"status": "unavailable", "malicious": None, "source": "VirusTotal"}

    if not settings.virustotal_api_key:
        return {"status": "unknown", "malicious": None, "source": "VirusTotal"}

    try:
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": settings.virustotal_api_key},
            data={"url": url},
            timeout=10,
        )
        r.raise_for_status()
        analysis_id = r.json()["data"]["id"]

        a = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=10,
        )
        a.raise_for_status()
        stats = a.json()["data"]["attributes"].get("stats", {})
        malicious = int(stats.get("malicious", 0)) > 0

        return {
            "status": "malicious" if malicious else "clean",
            "malicious": malicious,
            "stats": stats,
            "source": "VirusTotal",
        }
    except Exception as e:
        return {"status": "error", "malicious": None, "source": "VirusTotal", "error": str(e)}

def check_safe_browsing(url: str):
    if requests is None:
        return {"status": "unavailable", "malicious": None, "source": "Safe Browsing"}

    if not settings.google_safe_browsing_api_key:
        return {"status": "unknown", "malicious": None, "source": "Safe Browsing"}

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={settings.google_safe_browsing_api_key}"
    )
    payload = {
        "client": {"clientId": "phishing-detection-prototype", "clientVersion": "1.0"},
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
        r = requests.post(endpoint, json=payload, timeout=10)
        r.raise_for_status()
        data = r.json()
        malicious = bool(data.get("matches"))
        return {
            "status": "malicious" if malicious else "clean",
            "malicious": malicious,
            "source": "Safe Browsing",
            "matches": data.get("matches", []),
        }
    except Exception as e:
        return {"status": "error", "malicious": None, "source": "Safe Browsing", "error": str(e)}

def analyze_url(url: str):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    suspicious_terms = [
        "login", "verify", "secure", "account", "update", "support",
        "auth", "payroll", "invoice", "bank", "leak"
    ]
    heuristic = 0.0
    reasons = []
    full_url = url.lower()

    if parsed.scheme != "https":
        heuristic += 0.25
        reasons.append("URL does not use HTTPS")

    if len(url) > 120:
        heuristic += 0.10
        reasons.append("Unusually long URL")

    if any(term in full_url for term in suspicious_terms):
        heuristic += 0.25
        reasons.append("URL contains account, payment, or authentication terms")

    if "-" in domain:
        heuristic += 0.10
        reasons.append("Domain uses hyphenated words often seen in impersonation URLs")

    known_brands = ["microsoft", "office365", "paypal", "google", "apple", "amazon", "hdfc"]
    if any(brand in domain for brand in known_brands) and not domain.endswith((
        "microsoft.com",
        "office.com",
        "paypal.com",
        "google.com",
        "apple.com",
        "amazon.com",
        "hdfcbank.com",
    )):
        heuristic += 0.20
        reasons.append("Domain appears to impersonate a known brand")

    typo_domains = {"hdfe.com", "hdfc.com"}
    if domain.removeprefix("www.") in typo_domains:
        heuristic += 0.25
        reasons.append("Domain resembles a banking brand or typo-squatted site")

    vt = check_virustotal(url)
    sb = check_safe_browsing(url)

    if vt.get("malicious") is True:
        heuristic += 0.55
        reasons.append("VirusTotal reports malicious activity")

    if sb.get("malicious") is True:
        heuristic += 0.55
        reasons.append("Google Safe Browsing reports a threat")

    return {
        "url": url,
        "domain": domain,
        "risk": min(1.0, heuristic),
        "reasons": reasons,
        "virustotal": vt,
        "safe_browsing": sb,
    }
