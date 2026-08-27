import re
from bs4 import BeautifulSoup

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"]+", re.I)

def extract_urls(text: str):
    urls = []
    for url in URL_RE.findall(text or ""):
        normalized = url.rstrip(".,);]")
        if normalized.lower().startswith("www."):
            normalized = f"http://{normalized}"
        urls.append(normalized)
    return list(dict.fromkeys(urls))

def parse_email(sender, recipient, subject, body, headers, attachments):
    text = f"{subject}\n{body}"
    return {
        "sender": sender.strip(),
        "recipient": recipient,
        "subject": subject,
        "body": BeautifulSoup(body or "", "html.parser").get_text(" ", strip=True),
        "headers": headers or {},
        "urls": extract_urls(text),
        "attachments": attachments or [],
    }
