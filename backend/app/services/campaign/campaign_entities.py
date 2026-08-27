import re
import urllib.parse
from typing import List, Dict, Any, Tuple
import uuid

# Patterns for entity extraction
URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"]+", re.I)
PHONE_REGEX = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}")

# Context intent patterns
INTENT_TERMS = {
    "credential_verification": ["verify your account", "confirm identity", "password reset", "re-authenticate", "login", "sso", "credentials", "auth", "/auth"],
    "compliance_lure": ["compliance notice", "compliance", "mandatory compliance", "review the attached", "attached compliance", "compliance update", "security notification"],
    "urgency": ["immediately", "within 24 hours", "within 10 minutes", "account suspended", "urgent", "action required", "block", "proposal req"],
    "financial_payment": ["invoice", "payment", "wire transfer", "bank account", "refund", "salary", "payroll", "deposit", "finances", "financial"],
    "brand_impersonation": ["microsoft", "google", "apple", "paypal", "docusign", "sbi", "icici", "hdfc", "axis", "amazon"]
}

PUBLIC_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "me-qr.com", "qrco.de"}
GENERIC_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "google.com", "microsoft.com", "apple.com", "facebook.com"}

def normalize_url(url: str) -> str:
    """Strips trailing slashes, fragments, and standardizes scheme."""
    if not url:
        return ""
    u = url.strip()
    if u.lower().startswith("www."):
        u = "http://" + u
    try:
        parsed = urllib.parse.urlparse(u)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower().removeprefix("www.")
        path = parsed.path.rstrip("/")
        query = ("?" + parsed.query) if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return u.lower()

def extract_registrable_domain(url_or_domain: str) -> str:
    """Extracts base domain (e.g. login.evil-domain.com -> evil-domain.com)."""
    if not url_or_domain:
        return ""
    target = url_or_domain.strip().lower()
    if "://" in target:
        try:
            target = urllib.parse.urlparse(target).netloc
        except Exception:
            pass
    target = target.split(":")[0].removeprefix("www.")
    
    parts = target.split(".")
    if len(parts) >= 2:
        # Check double TLDs (e.g. .co.in, .gov.uk)
        if len(parts) >= 3 and parts[-2] in ("co", "com", "gov", "org", "net", "ac", "edu", "res") and len(parts[-1]) <= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return target

def normalize_phone_number(phone_str: str) -> str:
    """Normalizes phone numbers to standard digit representation."""
    if not phone_str:
        return ""
    digits = re.sub(r"[^\d+]", "", phone_str.strip())
    if len(digits) >= 7:
        return digits
    return ""

def mask_phone_number(phone_str: str) -> str:
    """Masks middle digits of phone numbers for UI privacy."""
    if not phone_str:
        return ""
    digits = re.sub(r"\D", "", phone_str)
    if len(digits) >= 10:
        if digits.startswith("91") and len(digits) == 12:
            return f"+91 {digits[2:6]}*****{digits[-2:]}"
        return f"+91 {digits[:4]}*****{digits[-2:]}"
    return phone_str

def extract_text_intents(text: str) -> List[str]:
    if not text:
        return []
    text_low = text.lower()
    intents = []
    for intent_name, keywords in INTENT_TERMS.items():
        if any(kw in text_low for kw in keywords):
            intents.append(intent_name)
    return intents

def extract_entities_from_text(text: str) -> Tuple[List[str], List[str], List[str]]:
    """Extracts (urls, domains, phone_numbers) from arbitrary text."""
    if not text:
        return [], [], []

    raw_urls = URL_REGEX.findall(text)
    clean_urls = []
    domains = []
    for u in raw_urls:
        norm_u = normalize_url(u.rstrip(".,;:!?'\")}]"))
        if norm_u:
            clean_urls.append(norm_u)
            dom = extract_registrable_domain(norm_u)
            if dom and dom not in GENERIC_DOMAINS and dom not in PUBLIC_SHORTENERS:
                domains.append(dom)

    raw_phones = PHONE_REGEX.findall(text)
    clean_phones = [normalize_phone_number(p) for p in raw_phones if len(normalize_phone_number(p)) >= 7]

    return list(dict.fromkeys(clean_urls)), list(dict.fromkeys(domains)), list(dict.fromkeys(clean_phones))
