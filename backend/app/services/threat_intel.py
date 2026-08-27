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

    known_brand_domains = {
        "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "msn.com"],
        "google": ["google.com", "gmail.com", "googlemail.com"],
        "apple": ["apple.com", "icloud.com"],
        "paypal": ["paypal.com"],
        "amazon": ["amazon.com", "aws.amazon.com"],
        "hdfc": ["hdfcbank.com"],
        "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
        "icici": ["icicibank.com"],
        "axis": ["axisbank.com"],
        "paytm": ["paytm.com"],
        "chase": ["chase.com"],
        "wellsfargo": ["wellsfargo.com"],
    }

    matched_brand = None
    for brand, legit_domains in known_brand_domains.items():
        if brand in domain:
            if not any(domain == legit or domain.endswith("." + legit) for legit in legit_domains):
                heuristic += 0.40
                reasons.append(f"Domain '{domain}' impersonates brand '{brand.upper()}' from an unauthorized domain")
                matched_brand = brand
                break

    clean_dom = domain.removeprefix("www.")
    # Check typosquatting / lookalike heuristics (e.g. sbxic, hdfe, sbi-login)
    typo_targets = ["sbi", "icici", "hdfc", "axis", "paytm", "paypal", "chase"]
    if not matched_brand:
        for b in typo_targets:
            # Check if brand substring combined with suspicious letters (e.g. sbxic contains sbi + icici or sbx)
            if (b in clean_dom or "sbi" in clean_dom or "icici" in clean_dom or "sbx" in clean_dom) and not any(clean_dom.endswith(legit) for legit in known_brand_domains.get(b, [])):
                heuristic += 0.45
                reasons.append(f"Domain '{domain}' exhibits banking brand lookalike or typosquatting characteristics ({b.upper()})")
                break

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
