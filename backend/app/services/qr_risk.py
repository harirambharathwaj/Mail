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
