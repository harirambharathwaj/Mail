from ..config import settings
from .parser import parse_email
from .analyzers import build_signals
from .fusion import fusion_model

def explain(verdict, signals, existing_reasons):
    reasons = list(existing_reasons)

    if signals["nlp_score"] >= 0.50:
        reasons.append("Language semantics analysis detected high phishing intent and urgency cues")
    if signals["url_score"] >= 0.40:
        reasons.append("Hyperlink risk scan flagged suspicious or unverified destination URLs")
    if signals["header_score"] >= 0.35:
        reasons.append("Sender/envelope inspection detected header, domain, or role impersonation anomalies")
    if signals["attachment_score"] >= 0.50:
        reasons.append("Attachment analysis detected executable or high-risk file types")
    if signals["sender_behavior_score"] >= 0.50:
        reasons.append("Sender historical behavioral profiling detected significant activity anomalies")

    if not reasons:
        reasons.append("Sender verified and no malicious threat indicators were detected")

    return list(dict.fromkeys(reasons))

def actions_for(verdict):
    if verdict == "SAFE":
        return ["ALLOW"]
    if verdict == "SUSPICIOUS":
        return ["ALERT", "REVIEW", "TAG_EXTERNAL"]
    if verdict == "PHISHING":
        return ["QUARANTINE", "ALERT", "BLOCK_SENDER"]
    return ["QUARANTINE", "HIGH_PRIORITY_ALERT", "SECURITY_OPS_ESCALATION"]

def analyze_email(request):
    email = parse_email(
        request.sender,
        request.recipient,
        request.subject,
        request.body,
        request.headers,
        request.attachments,
    )

    signals, initial_reasons, url_results, regional_payload = build_signals(
        email, settings.bert_model_path
    )

    # 1. Baseline machine learning fusion prediction (BERT + XGBoost remains untouched)
    verdict, confidence, probabilities, risk_score = fusion_model.predict(signals)

    # 2. Independent QR / Quishing post-model integration layer
    qr_analysis = email.get("quishing") or {}
    combined_urls = list(url_results)
    qr_reasons = []

    if qr_analysis.get("detected"):
        qr_risk_score = float(qr_analysis.get("risk_score", 0.0))
        qr_risk_level = qr_analysis.get("risk_level", "LOW")
        qr_reasons.extend(qr_analysis.get("reasons", []))

        # Merge decoded QR URLs into URL scan results
        for item in qr_analysis.get("items", []):
            final_u = item.get("final_url") or item.get("original_url")
            if final_u and not any(u.get("url") == final_u for u in combined_urls):
                intel = item.get("url_threat_intel") or {
                    "url": final_u,
                    "domain": final_u.split("/")[2] if "/" in final_u else final_u,
                    "risk": item.get("item_risk", 0.1),
                    "reasons": item.get("reasons", [])
                }
                combined_urls.append(intel)

        # Elevate final application result based on QR threat level
        if qr_risk_level == "HIGH":
            if verdict in ("SAFE", "SUSPICIOUS"):
                verdict = "PHISHING"
            risk_score = max(risk_score, round(qr_risk_score * 100, 2))
            confidence = max(confidence, 0.90)
        elif qr_risk_level == "MEDIUM":
            if verdict == "SAFE":
                verdict = "SUSPICIOUS"
            risk_score = max(risk_score, round(qr_risk_score * 100, 2))
            confidence = max(confidence, 0.78)

    all_reasons = explain(verdict, signals, initial_reasons + qr_reasons)

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "reasons": all_reasons,
        "signals": {
            **signals,
            "class_probabilities": probabilities,
        },
        "actions": actions_for(verdict),
        "urls": combined_urls,
        "quishing": qr_analysis,
        "regional": regional_payload,
    }
