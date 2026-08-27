from email.utils import parseaddr
from .bert_model import get_bert
from .threat_intel import analyze_url

URGENT_TERMS = ["urgent", "immediately", "within 10 minutes", "final warning", "account suspended"]
CREDENTIAL_TERMS = ["password", "otp", "one time password", "login", "verify your account", "credentials", "pin"]
MONEY_TERMS = ["transfer", "payment", "invoice", "bank account", "bank acc", "wire", "refund"]
DATA_EXPOSURE_TERMS = ["leak", "leaked", "data leak", "account leak", "bank account leak"]

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

KNOWN_BRANDS = {
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "msn.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "irs": ["irs.gov"],
    "irs-gov": ["irs.gov"],
    "netflix": ["netflix.com"],
    "hdfc": ["hdfcbank.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
}

INTERNAL_ROLES = [
    "ceo", "hr", "hr-system", "payroll", "finance", "finance-dept",
    "security", "security-alert", "admin", "admin-updates", "support",
    "billing", "helpdesk", "it-support", "accounts-payable", "executive"
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".work", ".click", ".buzz", ".cam", ".gq", ".cf", ".ml", ".tk", ".fit", ".rest", ".online", ".site"}

def analyze_headers(sender, recipient, headers):
    score = 0.0
    reasons = []
    
    sender_raw = str(sender or "").strip()
    recipient_raw = str(recipient or "").strip()
    
    sender_name, from_addr = parseaddr(sender_raw)
    from_addr = from_addr.lower()
    
    recipient_name, to_addr = parseaddr(recipient_raw)
    to_addr = to_addr.lower()
    
    reply_to_raw = str(headers.get("Reply-To", headers.get("reply-to", ""))).lower()
    
    # 1. Check Reply-To address redirection traps
    if reply_to_raw and from_addr:
        reply_name, reply_addr = parseaddr(reply_to_raw)
        if reply_addr and reply_addr != from_addr:
            score += 0.40
            reasons.append(f"Reply-To address '{reply_addr}' differs from sender '{from_addr}' (potential response redirection)")

    domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    recipient_domain = to_addr.split("@")[-1] if "@" in to_addr else ""
    local_part = from_addr.split("@", 1)[0] if "@" in from_addr else ""

    if not domain or "." not in domain:
        score += 0.30
        reasons.append("Sender domain is missing or malformed")
        return min(1.0, score), reasons

    # 2. Check for suspicious TLDs
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 0.35
        reasons.append(f"Sender uses high-risk suspicious TLD: {domain}")

    # 3. Check for free-mail random address heuristics
    if domain in {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com"}:
        letters = sum(ch.isalpha() for ch in local_part)
        unique_letters = len({ch for ch in local_part if ch.isalpha()})
        if letters >= 10 and unique_letters >= 6:
            score += 0.25
            reasons.append("Free-mail sender address appears algorithmically generated")

    # 4. Sender vs Recipient Relationship Analysis
    if recipient_domain:
        # Same domain = legitimate internal communication (if no reply-to spoof)
        if domain == recipient_domain:
            if not reply_to_raw or reply_addr == from_addr:
                # Authentic internal message
                pass
        else:
            # External sender to internal recipient
            recip_org = recipient_domain.split(".")[0].lower()
            sender_org = domain.split(".")[0].lower()
            
            # A) Lookalike / Spoofed Corporate Domain targeting recipient organization
            is_lookalike = False
            lookalike_patterns = ["-internal", "-corp", "-support", "-login", "-portal", "-security", "-auth", "-sync", "-update", "-system"]
            if len(recip_org) >= 3:
                # Substring lookalike e.g. "mycompany-internal.com" vs "mycompany.com"
                if any(f"{recip_org}{pat}" in domain for pat in lookalike_patterns) or any(f"{pat}{recip_org}" in domain for pat in lookalike_patterns):
                    is_lookalike = True
                # Typosquatting distance check e.g. "mycornpany.com"
                elif 0 < levenshtein_distance(sender_org, recip_org) <= 2:
                    is_lookalike = True

            if is_lookalike:
                score += 0.85
                reasons.append(f"Sender domain '{domain}' is a deceptive lookalike spoofing recipient domain '{recipient_domain}' (targeted spear-phishing)")

            # B) Sensitive Internal Role Impersonation from External Domain
            matched_role = None
            for role in INTERNAL_ROLES:
                if local_part == role or role in local_part.replace(".", "-").replace("_", "-").split("-"):
                    matched_role = role
                    break
            
            if matched_role and not is_lookalike:
                score += 0.45
                reasons.append(f"External sender '{from_addr}' attempts internal organizational role impersonation ('{matched_role}')")

    # 5. Known Brand / Service Impersonation in Sender Domain
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in domain:
            if not any(domain == legit or domain.endswith("." + legit) for legit in legit_domains):
                score += 0.80
                reasons.append(f"Sender domain '{domain}' impersonates brand '{brand.upper()}' from an unauthorized host")
                break

    # 6. Display Name Spoofing Check
    if sender_name:
        s_name_lower = sender_name.lower()
        for brand in KNOWN_BRANDS:
            if brand in s_name_lower and not any(domain.endswith(legit) for legit in KNOWN_BRANDS[brand]):
                score += 0.40
                reasons.append(f"Display name '{sender_name}' claims to be '{brand.upper()}' but envelope is from '{domain}'")
                break

    # 7. Authentication Header Checks (SPF, DKIM, DMARC)
    for k, v in headers.items():
        k_low = str(k).lower()
        v_low = str(v).lower()
        if any(auth_key in k_low for auth_key in ["spf", "dkim", "dmarc", "authentication"]):
            if "fail" in v_low or "softfail" in v_low:
                score += 0.50
                reasons.append(f"Email authentication failure detected in header '{k}'")
                break

    return min(1.0, round(score, 4)), reasons

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

def analyze_attachments(attachments, quishing_meta=None):
    risk = 0.0
    reasons = []
    risky_ext = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".iso", ".hta", ".xlsm", ".docm"}

    for item in (attachments or []):
        name = ""
        if isinstance(item, dict):
            name = str(item.get("name", "")).lower()
        elif isinstance(item, str):
            name = str(item).lower()

        for ext in risky_ext:
            if name.endswith(ext):
                risk = max(risk, 0.85)
                reasons.append(f"Potentially dangerous executable/script attachment type: {ext}")

    if quishing_meta and quishing_meta.get("detected"):
        risk = max(risk, 0.75)
        reasons.extend(quishing_meta.get("reasons", []))

    return min(1.0, risk), reasons

def analyze_sender_behavior(sender, headers):
    # Prototype: use explicit behavior_anomaly if supplied.
    if isinstance(headers, dict) and headers.get("behavior_anomaly") is not None:
        try:
            return float(headers["behavior_anomaly"]), ["Sender behavior marked anomalous"]
        except (ValueError, TypeError):
            pass
    return 0.0, []

def build_signals(email, model_path):
    combined_text = f"{email.get('subject', '')}\n{email.get('body', '')}"

    header_score, header_reasons = analyze_headers(email.get("sender", ""), email.get("recipient", ""), email.get("headers", {}))
    nlp_score, body_reasons = analyze_body(combined_text, model_path)
    attachment_score, attachment_reasons = analyze_attachments(email.get("attachments", []), email.get("quishing"))
    behavior_score, behavior_reasons = analyze_sender_behavior(email.get("sender", ""), email.get("headers", {}))

    url_results = [analyze_url(url) for url in email.get("urls", [])]
    url_score = max([x["risk"] for x in url_results], default=0.0)

    url_reasons = []
    for result in url_results:
        url_reasons.extend(result.get("reasons", []))

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
