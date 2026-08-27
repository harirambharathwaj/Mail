from ..config import settings
from .parser import parse_email
from .analyzers import build_signals
from .fusion import fusion_model

def explain(verdict, signals, existing_reasons):
    reasons = list(existing_reasons)

    if signals["nlp_score"] >= 0.65:
        reasons.append("NLP model detected phishing-like language or intent")
    if signals["url_score"] >= 0.50:
        reasons.append("URL analysis produced a high-risk signal")
    if signals["header_score"] >= 0.40:
        reasons.append("Header/sender analysis produced an anomaly")
    if signals["attachment_score"] >= 0.50:
        reasons.append("Attachment analysis produced a high-risk signal")
    if signals["sender_behavior_score"] >= 0.50:
        reasons.append("Sender behavior differs from the baseline")

    if not reasons:
        reasons.append("No strong malicious indicators were detected")

    return list(dict.fromkeys(reasons))

def actions_for(verdict):
    if verdict == "SAFE":
        return ["ALLOW"]
    if verdict == "SUSPICIOUS":
        return ["ALERT", "REVIEW"]
    if verdict == "PHISHING":
        return ["QUARANTINE", "ALERT"]
    return ["QUARANTINE", "HIGH_PRIORITY_ALERT"]

def analyze_email(request):
    email = parse_email(
        request.sender,
        request.recipient,
        request.subject,
        request.body,
        request.headers,
        request.attachments,
    )

    signals, initial_reasons, url_results = build_signals(
        email, settings.bert_model_path
    )

    verdict, confidence, probabilities = fusion_model.predict(signals)

    # Application-level display score. 0-100 here; choose/validate a policy before production.
    safe_prob = probabilities.get("SAFE", confidence if verdict == "SAFE" else 1.0 - confidence)
    risk_score = round((1.0 - safe_prob) * 100, 2)

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": round(confidence, 4),
        "reasons": explain(verdict, signals, initial_reasons),
        "signals": {
            **signals,
            "class_probabilities": probabilities,
        },
        "actions": actions_for(verdict),
        "urls": url_results,
    }
