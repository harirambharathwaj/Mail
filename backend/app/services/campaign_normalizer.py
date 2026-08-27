import re
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from .language_id import detect_language

COMMON_BENIGN_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "paypal.com",
    "whatsapp.com", "facebook.com", "amazon.com", "github.com",
    "linkedin.com", "netflix.com", "twitter.com", "x.com"
}

def extract_registered_domain(hostname: str) -> str:
    if not hostname:
        return ""
    host = hostname.lower().strip()
    # Strip port if present
    if ":" in host:
        host = host.split(":")[0]
    # Strip trailing dot
    host = host.rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Handle two-part ccTLDs like .co.in, .co.uk, .gov.in, .ac.in
    two_part_tlds = {"co.in", "gov.in", "ac.in", "co.uk", "org.uk", "com.au", "co.jp"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def normalize_phone_number(raw_phone: str) -> Dict[str, str]:
    if not raw_phone:
        return {"canonical": "", "masked": ""}
    # Strip whitespace, dashes, parentheses
    cleaned = re.sub(r"[^\d+]", "", str(raw_phone))
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    elif not cleaned.startswith("+") and len(cleaned) == 10:
        cleaned = "+91" + cleaned # Standard Indian mobile prefix fallback
    elif not cleaned.startswith("+"):
        cleaned = "+" + cleaned

    # Create masked representation for privacy
    if len(cleaned) > 6:
        masked = cleaned[:4] + "*" * (len(cleaned) - 6) + cleaned[-2:]
    else:
        masked = cleaned[:2] + "****"

    return {"canonical": cleaned, "masked": masked}

def normalize_timestamp(ts_raw: Any) -> str:
    if not ts_raw:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(ts_raw, (int, float)):
        try:
            return datetime.fromtimestamp(ts_raw, tz=timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
    s = str(ts_raw).strip()
    try:
        # Try ISO format
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.isoformat()
    except Exception:
        # Common date patterns
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d-%m-%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except Exception:
                pass
    return datetime.now(timezone.utc).isoformat()

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    url_pattern = r'(?:https?://|www\.)[a-zA-Z0-9.\-_~:/?#\[\]@!$&\'()*+,;=%]+'
    found = re.findall(url_pattern, text)
    normalized_urls = []
    for u in found:
        u_clean = u.rstrip(".,;!?'\")>")
        if not u_clean.startswith("http://") and not u_clean.startswith("https://"):
            u_clean = "http://" + u_clean
        normalized_urls.append(u_clean)
    return list(dict.fromkeys(normalized_urls))

class NormalizedEvent:
    def __init__(self, raw: Dict[str, Any], event_idx: int = 1):
        self.event_id = str(raw.get("event_id") or f"EVT_{event_idx:03d}")
        self.channel = str(raw.get("channel") or "email").lower()
        if self.channel not in ("email", "sms", "whatsapp"):
            self.channel = "email"
        
        self.timestamp = normalize_timestamp(raw.get("timestamp"))
        self.raw_sender = str(raw.get("sender") or "").strip()
        self.recipient = str(raw.get("recipient") or "").strip()
        self.subject = str(raw.get("subject") or "").strip()
        self.body = str(raw.get("body") or raw.get("text") or "").strip()
        
        # Combined text for semantic analysis
        self.full_text = f"{self.subject} {self.body}".strip()
        
        # Language Identification
        self.lang_meta = detect_language(self.full_text)
        
        # Phone normalization (especially for SMS / WhatsApp)
        phone_info = normalize_phone_number(self.raw_sender) if any(c.isdigit() for c in self.raw_sender) else {"canonical": "", "masked": ""}
        self.sender_phone = phone_info["canonical"]
        self.sender_phone_masked = phone_info["masked"]
        
        # Email sender domain normalization
        if "@" in self.raw_sender:
            domain_part = self.raw_sender.split("@")[-1].lower().strip()
            self.sender_domain = extract_registered_domain(domain_part)
        else:
            self.sender_domain = ""

        # Extract URLs
        explicit_urls = raw.get("urls") or []
        if isinstance(explicit_urls, str):
            try:
                explicit_urls = json.loads(explicit_urls)
            except Exception:
                explicit_urls = [explicit_urls]
        
        text_urls = extract_urls(self.full_text)
        all_raw_urls = list(dict.fromkeys(list(explicit_urls) + text_urls))
        
        # Structured URL / Domain entities
        self.urls = []
        self.domains = []
        self.registered_domains = []
        self.url_paths = []
        
        for u in all_raw_urls:
            try:
                parsed = urllib.parse.urlparse(u)
                host = parsed.netloc.lower()
                reg_dom = extract_registered_domain(host)
                path = parsed.path.rstrip("/")
                
                self.urls.append(u)
                if host and host not in self.domains:
                    self.domains.append(host)
                if reg_dom and reg_dom not in self.registered_domains:
                    self.registered_domains.append(reg_dom)
                if path and len(path) > 1:
                    self.url_paths.append(path)
            except Exception:
                pass

        # QR and Attachment payloads
        self.qr_payloads = list(raw.get("qr_payloads") or [])
        self.attachments = list(raw.get("attachments") or [])
        self.origin = str(raw.get("origin") or "user_input")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "channel": self.channel,
            "timestamp": self.timestamp,
            "sender_masked": self.sender_phone_masked if self.sender_phone else self.raw_sender,
            "sender_domain": self.sender_domain,
            "subject": self.subject,
            "body": self.body,
            "language": self.lang_meta.get("language", "en"),
            "script": self.lang_meta.get("script", "latin"),
            "code_mixed": self.lang_meta.get("code_mixed", False),
            "urls": self.urls,
            "registered_domains": self.registered_domains,
            "origin": self.origin
        }
