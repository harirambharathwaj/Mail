from typing import List, Dict, Any, Tuple

def evaluate_qr_item_risk(item: Dict[str, Any], url_intel: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Evaluates risk score (0.0 to 1.0) and generates explicit explainable reasons for a single decoded QR item.
    A legitimate QR remains legitimate (Low risk ~0.05).
    """
    risk = 0.05
    reasons = []

    source = item.get("source", "attachment")
    filename = item.get("filename", "")
    page = item.get("page")
    payload_type = item.get("payload_type", "")
    redirect_count = item.get("redirect_count", 0)
    intents = item.get("context_intents", [])
    ocr_text = item.get("ocr_text", "")
    final_url = item.get("final_url", item.get("payload", ""))

    # 1. Source & location note
    if source == "pdf_attachment" and page:
        reasons.append(f"QR code detected on page {page} of PDF document '{filename}'")
    elif filename:
        reasons.append(f"QR code detected inside attachment '{filename}'")
    else:
        reasons.append("QR code detected within email body image")

    # 2. Payload classification
    if payload_type in ("http_url", "https_url", "url"):
        # URL payload
        if payload_type == "http_url" and final_url.lower().startswith("http://"):
            risk += 0.20
            reasons.append("QR payload resolves to unencrypted HTTP destination")

        # Redirect behaviors
        if redirect_count >= 2:
            risk += 0.25
            reasons.append(f"QR destination uses multi-hop redirection ({redirect_count} hops) to obscure final endpoint")
        elif redirect_count == 1:
            risk += 0.10
            reasons.append("QR destination routes through a redirect link shortener")

        # URL Threat Intelligence & Heuristics
        if url_intel:
            url_risk = float(url_intel.get("risk", 0.0))
            if url_risk >= 0.50:
                risk += 0.45
                reasons.append("Decoded destination URL flagged with high threat / impersonation risk")
            elif url_risk >= 0.25:
                risk += 0.20
                reasons.append("Decoded destination URL exhibits suspicious domain characteristics")

            # Add specific URL threat intelligence reasons
            for r in url_intel.get("reasons", []):
                if r not in reasons:
                    reasons.append(f"URL intelligence: {r}")

            # VirusTotal & Safe Browsing
            if url_intel.get("virustotal", {}).get("malicious") is True:
                risk += 0.50
                reasons.append("VirusTotal confirms malicious activity on QR destination")

            if url_intel.get("safe_browsing", {}).get("malicious") is True:
                risk += 0.50
                reasons.append("Google Safe Browsing reports security threat on QR destination")

    elif payload_type == "mailto":
        risk += 0.15
        reasons.append("QR code initiates automated mailto message dispatch")
    elif payload_type == "tel":
        risk += 0.15
        reasons.append("QR code triggers direct telephone dialing intent")
    elif payload_type == "plain_text":
        # Check if plain text contains credential lures
        pass

    # 3. Contextual OCR / Intent Corroboration
    if "credential_verification" in intents:
        risk += 0.25
        reasons.append("Surrounding document text demands credential, login, or MFA re-verification")

    if "urgency" in intents:
        risk += 0.15
        reasons.append("Urgent countdown or account termination language accompanies QR code")

    if "payment_invoice" in intents:
        risk += 0.15
        reasons.append("Financial payment or overdue invoice context associated with QR code")

    if "brand_impersonation" in intents and risk >= 0.35:
        risk += 0.15
        reasons.append("Document claims corporate brand authority to induce QR scan")

    # Bound risk between 0.05 and 0.99
    final_risk = min(0.99, max(0.05, round(risk, 4)))
    return final_risk, reasons

def calculate_overall_qr_risk(qr_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregates multi-QR findings into a unified, explainable QR analysis report.
    """
    if not qr_items:
        return {
            "detected": False,
            "count": 0,
            "risk_score": 0.0,
            "risk_level": "LOW",
            "reasons": ["No QR codes detected in email body or attachments"],
            "items": []
        }

    item_risks = [item.get("item_risk", 0.05) for item in qr_items]
    max_risk = max(item_risks) if item_risks else 0.05

    # Multi-QR escalation if multiple high-risk QRs
    high_risk_count = sum(1 for r in item_risks if r >= 0.60)
    if high_risk_count > 1:
        max_risk = min(0.99, max_risk + 0.10)

    # Classify overall risk level
    if max_risk >= 0.70:
        risk_level = "HIGH"
    elif max_risk >= 0.30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Consolidate distinct reasons across all QR items
    all_reasons = []
    for item in qr_items:
        for r in item.get("reasons", []):
            if r not in all_reasons:
                all_reasons.append(r)

    if not all_reasons:
        if risk_level == "LOW":
            all_reasons.append("Legitimate QR code detected with clean destination and safe context")
        else:
            all_reasons.append("Anomalous QR code detected")

    return {
        "detected": True,
        "count": len(qr_items),
        "risk_score": round(max_risk, 4),
        "risk_level": risk_level,
        "reasons": all_reasons,
        "items": qr_items
    }

def evaluate_standalone_qr_risk(item: Dict[str, Any], url_intel: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes standalone QR Phishing detector risk score, risk level, visual risk breakdown,
    threat intelligence status, and explainable reasons.

    Risk Levels & Thresholds:
      0.00 - 0.29 -> SAFE
      0.30 - 0.59 -> LOW RISK
      0.60 - 0.79 -> SUSPICIOUS
      0.80 - 1.00 -> PHISHING
    """
    payload = item.get("payload", "")
    payload_type = item.get("payload_type", "url")
    original_url = item.get("original_url") or payload
    final_url = item.get("final_url") or original_url
    redirect_chain = item.get("redirect_chain", [original_url])
    redirect_count = item.get("redirect_count", 0)
    resolution_success = item.get("resolution_success", True)
    resolution_error = item.get("resolution_error")

    # Non-URL payloads (e.g. plain_text, mailto, tel)
    if payload_type not in ("http_url", "https_url", "url") and not original_url.lower().startswith(("http://", "https://", "www.")):
        reasons = [f"QR code decoded payload type: {payload_type.upper()}"]
        if payload_type == "plain_text":
            reasons.append("Payload is plain text and does not contain web URLs")
        elif payload_type == "mailto":
            reasons.append("QR code initiates automated mailto message dispatch")
        elif payload_type == "tel":
            reasons.append("QR code triggers direct telephone dialing intent")

        return {
            "success": True,
            "qr_detected": True,
            "payload_type": payload_type,
            "payload": payload,
            "decoded_url": payload,
            "is_https": False,
            "redirect_count": 0,
            "redirect_chain": [],
            "final_url": payload,
            "resolution_success": True,
            "resolution_error": None,
            "risk_score": 0.05,
            "risk_level": "SAFE",
            "message": f"QR decoded successfully. Payload type: {payload_type.upper()}. Phishing URL analysis is not applicable.",
            "reasons": reasons,
            "breakdown": {
                "url_structure": 0.0,
                "redirect_risk": 0.0,
                "threat_intel": 0.0,
                "destination_risk": 0.0,
                "overall": 0.05
            },
            "threat_intelligence": {
                "virustotal": {"configured": False, "status": "not_configured", "malicious": False},
                "safe_browsing": {"configured": False, "status": "not_configured", "malicious": False}
            }
        }

    # URL Payload Risk Analysis
    reasons = []
    url_struct_score = 0.0
    redirect_risk_score = 0.0
    intel_risk_score = 0.0
    dest_risk_score = 0.0

    target_url = final_url or original_url
    url_low = target_url.lower()
    is_https = url_low.startswith("https://")

    # 1. URL Structure Analysis
    if not is_https:
        url_struct_score += 0.35
        reasons.append("Unencrypted HTTP scheme detected (no TLS/SSL encryption)")

    import urllib.parse
    parsed = urllib.parse.urlparse(target_url)
    domain = (parsed.netloc or "").lower()

    # Check for IP address instead of domain name
    import re
    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        url_struct_score += 0.50
        reasons.append("Destination uses numeric IP address instead of a domain name")

    # Suspicious TLDs
    suspicious_tlds = [".xyz", ".top", ".work", ".club", ".info", ".biz", ".live", ".online", ".site", ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".icu"]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        url_struct_score += 0.35
        reasons.append(f"Destination domain uses high-risk suspicious TLD")

    # Credential/Login keywords in URL
    cred_keywords = ["login", "verify", "auth", "account", "signin", "password", "update", "secure", "mfa", "2fa", "bank", "pay", "invoice"]
    found_keywords = [kw for kw in cred_keywords if kw in url_low]
    if found_keywords:
        url_struct_score += 0.30
        dest_risk_score += 0.40
        reasons.append(f"Destination contains authentication / credential keywords: {', '.join(found_keywords[:3])}")

    # Impersonation hyphens or brand in subdomains
    known_brands = ["microsoft", "office365", "google", "apple", "paypal", "amazon", "docusign"]
    if any(b in url_low for b in known_brands) and not any(domain.endswith("." + b + ".com") or domain == b + ".com" for b in known_brands):
        url_struct_score += 0.35
        dest_risk_score += 0.35
        reasons.append("Domain exhibits brand impersonation / typosquatting characteristics")

    # Excessively long URL
    if len(target_url) > 100:
        url_struct_score += 0.15
        reasons.append("Excessively long URL structure detected (>100 chars)")

    # 2. Redirect Analysis
    if redirect_count >= 2:
        redirect_risk_score += 0.85
        reasons.append(f"Multiple HTTP redirects detected ({redirect_count} hops) hiding final destination")
    elif redirect_count == 1:
        redirect_risk_score += 0.40
        reasons.append("Single-hop HTTP redirect detected")

    # Check for shorteners
    shortener_domains = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly"]
    orig_parsed = urllib.parse.urlparse(original_url)
    orig_domain = (orig_parsed.netloc or "").lower()
    if any(s in orig_domain for s in shortener_domains):
        redirect_risk_score += 0.45
        reasons.append("URL shortener service utilized to conceal original target domain")

    if not resolution_success and resolution_error:
        redirect_risk_score += 0.70
        reasons.append(f"Redirect resolution security notice: {resolution_error}")

    # 3. Threat Intelligence Analysis
    vt_res = url_intel.get("virustotal", {})
    sb_res = url_intel.get("safe_browsing", {})

    vt_configured = vt_res.get("status") not in ("unknown", "unavailable", None)
    sb_configured = sb_res.get("status") not in ("unknown", "unavailable", None)

    vt_malicious = bool(vt_res.get("malicious")) if vt_configured else False
    sb_malicious = bool(sb_res.get("malicious")) if sb_configured else False

    if vt_malicious:
        intel_risk_score += 1.0
        reasons.append("VirusTotal threat database confirms malicious detection")
    if sb_malicious:
        intel_risk_score += 1.0
        reasons.append("Google Safe Browsing reports security threat on destination URL")

    url_intel_risk = float(url_intel.get("risk", 0.0))
    if url_intel_risk >= 0.5:
        intel_risk_score += 0.60
        for r in url_intel.get("reasons", []):
            if r not in reasons:
                reasons.append(f"Threat intelligence: {r}")

    # 4. Destination Risk Analysis
    if not is_https and ("login" in url_low or "verify" in url_low):
        dest_risk_score += 0.50
        reasons.append("Unencrypted destination collecting sensitive credentials")

    # Normalize scores between 0.0 and 1.0
    url_struct_score = min(1.0, round(url_struct_score, 2))
    redirect_risk_score = min(1.0, round(redirect_risk_score, 2))
    intel_risk_score = min(1.0, round(intel_risk_score, 2))
    dest_risk_score = min(1.0, round(dest_risk_score, 2))

    # Overall Risk Score Calculation
    weighted_score = (
        0.35 * url_struct_score +
        0.25 * redirect_risk_score +
        0.25 * intel_risk_score +
        0.15 * dest_risk_score
    )

    if vt_malicious or sb_malicious:
        weighted_score = max(0.92, weighted_score)

    # Boost if multiple high-risk indicators match
    if url_struct_score >= 0.6 and redirect_risk_score >= 0.4:
        weighted_score = max(0.82, weighted_score)

    # Multi-hop redirect escalation
    if redirect_count >= 2:
        weighted_score = max(0.65, weighted_score)

    if redirect_count >= 2 and (url_struct_score >= 0.3 or dest_risk_score >= 0.3):
        weighted_score = max(0.85, weighted_score)

    overall_risk = min(1.0, max(0.02, round(weighted_score, 2)))


    # Classification Thresholds
    if overall_risk >= 0.80:
        risk_level = "PHISHING"
    elif overall_risk >= 0.60:
        risk_level = "SUSPICIOUS"
    elif overall_risk >= 0.30:
        risk_level = "LOW RISK"
    else:
        risk_level = "SAFE"

    if not reasons:
        reasons.append("Valid HTTPS destination with clean URL structure and no threat intelligence flags")

    return {
        "success": True,
        "qr_detected": True,
        "payload_type": payload_type,
        "payload": payload,
        "decoded_url": original_url,
        "is_https": is_https,
        "redirect_count": redirect_count,
        "redirect_chain": redirect_chain,
        "final_url": target_url,
        "resolution_success": resolution_success,
        "resolution_error": resolution_error,
        "risk_score": overall_risk,
        "risk_level": risk_level,
        "reasons": reasons,
        "breakdown": {
            "url_structure": url_struct_score,
            "redirect_risk": redirect_risk_score,
            "threat_intel": intel_risk_score,
            "destination_risk": dest_risk_score,
            "overall": overall_risk
        },
        "threat_intelligence": {
            "virustotal": {
                "configured": vt_configured,
                "status": "clean" if vt_configured and not vt_malicious else ("malicious" if vt_malicious else "not_configured"),
                "malicious": vt_malicious,
                "message": "No malicious detections" if vt_configured and not vt_malicious else ("Malicious threat detected" if vt_malicious else "VirusTotal API key not configured")
            },
            "safe_browsing": {
                "configured": sb_configured,
                "status": "clean" if sb_configured and not sb_malicious else ("malicious" if sb_malicious else "not_configured"),
                "malicious": sb_malicious,
                "message": "No threat detected" if sb_configured and not sb_malicious else ("Security threat reported" if sb_malicious else "Google Safe Browsing API key not configured")
            }
        }
    }

