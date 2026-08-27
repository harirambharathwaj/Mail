from email.utils import parseaddr
from .bert_model import get_bert
from .threat_intel import analyze_url

URGENT_TERMS = ["urgent", "immediately", "within 10 minutes", "final warning", "account suspended"]
CREDENTIAL_TERMS = ["password", "otp", "one time password", "login", "verify your account", "credentials", "pin"]
MONEY_TERMS = ["transfer", "payment", "invoice", "bank account", "bank acc", "wire", "refund"]
DATA_EXPOSURE_TERMS = ["leak", "leaked", "data leak", "account leak", "bank account leak"]

def analyze_headers(sender, headers):
    score = 0.0
    reasons = []
    from_addr = parseaddr(sender)[1].lower()
    reply_to = str(headers.get("Reply-To", "")).lower()

    if reply_to and from_addr:
        reply_addr = parseaddr(reply_to)[1].lower()
        if reply_addr and reply_addr != from_addr:
            score += 0.35
            reasons.append("Reply-To address differs from sender address")

    domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    if not domain or "." not in domain:
        score += 0.20
        reasons.append("Sender domain looks malformed")

    local_part = from_addr.split("@", 1)[0] if "@" in from_addr else ""
    if domain in {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com"}:
        letters = sum(ch.isalpha() for ch in local_part)
        unique_letters = len({ch for ch in local_part if ch.isalpha()})
        has_random_shape = letters >= 10 and unique_letters >= 6
        if has_random_shape:
            score += 0.20
            reasons.append("Free-mail sender address looks randomly generated")

    return min(1.0, score), reasons

def analyze_body(text, model_path):
    model = get_bert(model_path)
    score = model.predict(text)
    reasons = []
    low = text.lower()

    if any(x in low for x in URGENT_TERMS):
        reasons.append("Urgent or threatening language detected")
    if any(x in low for x in CREDENTIAL_TERMS):
        reasons.append("Credential/account verification request detected")
    if any(x in low for x in MONEY_TERMS):
        reasons.append("Financial/payment language detected")
    if any(x in low for x in DATA_EXPOSURE_TERMS):
        reasons.append("Account or data exposure language detected")

    return score, reasons

def analyze_attachments(attachments):
    risk = 0.0
    reasons = []
    risky_ext = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar"}

    for item in attachments:
        name = str(item.get("name", "")).lower()
        for ext in risky_ext:
            if name.endswith(ext):
                risk = max(risk, 0.8)
                reasons.append(f"Potentially dangerous attachment type: {ext}")

    return risk, reasons

def analyze_sender_behavior(sender, headers):
    # Prototype: use explicit behavior_anomaly if supplied.
    # Production version should calculate this from historical email data.
    if headers.get("behavior_anomaly") is not None:
        try:
            return float(headers["behavior_anomaly"]), ["Sender behavior marked anomalous"]
        except ValueError:
            pass
    return 0.0, []

def build_signals(email, model_path):
    combined_text = f"{email['subject']}\n{email['body']}"

    header_score, header_reasons = analyze_headers(email["sender"], email["headers"])
    nlp_score, body_reasons = analyze_body(combined_text, model_path)
    attachment_score, attachment_reasons = analyze_attachments(email["attachments"])
    behavior_score, behavior_reasons = analyze_sender_behavior(email["sender"], email["headers"])

    url_results = [analyze_url(url) for url in email["urls"]]
    url_score = max([x["risk"] for x in url_results], default=0.0)

    url_reasons = []
    for result in url_results:
        url_reasons.extend(result["reasons"])

    reasons = list(dict.fromkeys(
        header_reasons + body_reasons + url_reasons +
        attachment_reasons + behavior_reasons
    ))

    signals = {
        "nlp_score": round(float(nlp_score), 4),
        "url_score": round(float(url_score), 4),
        "header_score": round(float(header_score), 4),
        "attachment_score": round(float(attachment_score), 4),
        "sender_behavior_score": round(float(behavior_score), 4),
    }

    return signals, reasons, url_results
