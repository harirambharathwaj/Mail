import re
import json
from bs4 import BeautifulSoup

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"]+", re.I)
QR_PATTERNS = re.compile(r"(?:scan\s+(?:the|this)?\s*qr|qr[\s\-_]*code|authenticator\s+app\s+qr|mfa\s+qr|2fa\s+qr)", re.I)

def extract_urls(text: str):
    urls = []
    for url in URL_RE.findall(str(text or "")):
        normalized = url.rstrip(".,);]")
        if normalized.lower().startswith("www."):
            normalized = f"http://{normalized}"
        urls.append(normalized)
    return list(dict.fromkeys(urls))

def parse_email(sender, recipient, subject, body, headers, attachments):
    sender_str = str(sender or "").strip()
    recipient_str = str(recipient or "").strip()
    subject_str = str(subject or "").strip()
    body_str = str(body or "").strip()
    
    clean_body = BeautifulSoup(body_str or "", "html.parser").get_text(" ", strip=True) if body_str else ""
    full_text = f"{subject_str}\n{clean_body}"

    # Safely parse headers
    parsed_headers = {}
    if isinstance(headers, dict):
        parsed_headers = headers
    elif isinstance(headers, str) and headers.strip():
        try:
            parsed_headers = json.loads(headers)
        except Exception:
            parsed_headers = {"raw_header": headers}

    # Safely normalize attachments
    norm_attachments = []
    if isinstance(attachments, list):
        for item in attachments:
            if isinstance(item, dict):
                norm_attachments.append(item)
            elif isinstance(item, str) and item.strip():
                norm_attachments.append({"name": item.strip()})
    elif isinstance(attachments, str) and attachments.strip():
        try:
            loaded = json.loads(attachments)
            if isinstance(loaded, list):
                for item in loaded:
                    norm_attachments.append(item if isinstance(item, dict) else {"name": str(item)})
            elif isinstance(loaded, dict):
                norm_attachments.append(loaded)
            else:
                norm_attachments.append({"name": attachments.strip()})
        except Exception:
            norm_attachments.append({"name": attachments.strip()})

    # Extract inline base64 images if present in HTML body
    inline_images = []
    if "data:image/" in body_str:
        for match in re.findall(r'src=["\'](data:image/[^"\']+)["\']', body_str, re.I):
            inline_images.append(match)

    # Invoke full QR / Quishing analysis service
    try:
        from .qr_service import analyze_email_quishing
        qr_analysis = analyze_email_quishing(clean_body, norm_attachments, inline_images=inline_images)
    except Exception as e:
        qr_analysis = {
            "detected": False,
            "count": 0,
            "risk_score": 0.0,
            "risk_level": "LOW",
            "reasons": [f"QR scanner encountered error: {str(e)}"],
            "items": []
        }

    # Invoke Language Identification (LID)
    try:
        from .language_id import detect_language
        lang_analysis = detect_language(full_text)
    except Exception as e:
        lang_analysis = {
            "language": "unknown",
            "languages": ["unknown"],
            "script": "unknown",
            "code_mixed": False,
            "transliterated": False,
            "confidence": 0.50,
            "detected_markers": [],
            "summary": f"Language ID error: {str(e)}"
        }

    return {
        "sender": sender_str,
        "recipient": recipient_str,
        "subject": subject_str,
        "body": clean_body,
        "headers": parsed_headers,
        "urls": extract_urls(full_text),
        "attachments": norm_attachments,
        "quishing": qr_analysis,
        "regional": lang_analysis,
    }
