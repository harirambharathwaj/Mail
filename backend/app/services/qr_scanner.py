import io
import base64
import re
from typing import List, Dict, Any, Optional, Tuple, Union
import numpy as np
from PIL import Image
import cv2

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

# Regex patterns for QR payload categorization
URL_REGEX = re.compile(r"^(?:https?://|www\.)[^\s<>\"]+", re.I)
MAILTO_REGEX = re.compile(r"^mailto:([^?]+)", re.I)
TEL_REGEX = re.compile(r"^(?:tel:|telnet:|\+?\d{7,15}$)", re.I)

# Contextual intent patterns in OCR / surrounding text
INTENT_PATTERNS = {
    "credential_verification": [
        "verify your account", "confirm your identity", "password reset", "re-authenticate",
        "single sign-on", "sso verification", "security verification", "update credentials",
        "mfa update", "2fa setup", "authenticator app"
    ],
    "urgency": [
        "immediately", "within 24 hours", "within 10 minutes", "account suspended",
        "action required", "urgent", "immediate attention", "will be terminated"
    ],
    "payment_invoice": [
        "invoice", "overdue payment", "wire transfer", "remittance", "tax refund",
        "payroll update", "salary payout", "direct deposit"
    ],
    "brand_impersonation": [
        "microsoft", "office 365", "google workspace", "apple id", "docusign", "paypal", "it helpdesk"
    ]
}

def determine_payload_type(raw_text: str) -> str:
    """Classifies the decoded QR payload string into standard semantic types."""
    text_clean = str(raw_text or "").strip()
    if not text_clean:
        return "empty"
    if text_clean.lower().startswith("https://"):
        return "https_url"
    elif text_clean.lower().startswith("http://") or text_clean.lower().startswith("www."):
        return "http_url"
    elif MAILTO_REGEX.search(text_clean):
        return "mailto"
    elif TEL_REGEX.search(text_clean):
        return "tel"
    elif URL_REGEX.search(text_clean):
        return "url"
    else:
        return "plain_text"

def extract_ocr_context_intents(text: str) -> List[str]:
    """Identifies high-risk intent markers from OCR and surrounding text."""
    if not text:
        return []
    text_low = text.lower()
    intents = []
    for category, phrases in INTENT_PATTERNS.items():
        if any(p in text_low for p in phrases):
            intents.append(category)
    return intents

def detect_qr_in_cv2_image(image_bgr: np.ndarray) -> List[Dict[str, Any]]:
    """
    Scans a BGR/Grayscale OpenCV image array using cv2.QRCodeDetector.
    Handles multiple QRs, rotated angles, and returns decoded payloads and bounding boxes.
    """
    detected_items = []
    if image_bgr is None or image_bgr.size == 0:
        return detected_items

    detector = cv2.QRCodeDetector()

    # 1. Try detectAndDecodeMulti for multiple QRs in single image
    try:
        ok, decoded_info, points, _ = detector.detectAndDecodeMulti(image_bgr)
        if ok and decoded_info is not None:
            for idx, text in enumerate(decoded_info):
                if text and str(text).strip():
                    bbox = points[idx].tolist() if points is not None and len(points) > idx else None
                    detected_items.append({
                        "decoded": True,
                        "payload": str(text).strip(),
                        "payload_type": determine_payload_type(str(text).strip()),
                        "bounding_box": bbox
                    })
    except Exception:
        pass

    # 2. If multi-detector found nothing, try single-QR detector with pre-processing (Grayscale + Threshold)
    if not detected_items:
        try:
            text, points, _ = detector.detectAndDecode(image_bgr)
            if text and str(text).strip():
                bbox = points.tolist() if points is not None else None
                detected_items.append({
                    "decoded": True,
                    "payload": str(text).strip(),
                    "payload_type": determine_payload_type(str(text).strip()),
                    "bounding_box": bbox
                })
        except Exception:
            pass

    # 3. Fallback: Contrast enhancement & adaptive thresholding for low-contrast / dark mode QRs
    if not detected_items:
        try:
            if len(image_bgr.shape) == 3:
                gray = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2GRAY)
            else:
                gray = image_bgr
            
            # Contrast stretching / CLAHE
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(gray)
            text, points, _ = detector.detectAndDecode(enhanced)
            if text and str(text).strip():
                bbox = points.tolist() if points is not None else None
                detected_items.append({
                    "decoded": True,
                    "payload": str(text).strip(),
                    "payload_type": determine_payload_type(str(text).strip()),
                    "bounding_box": bbox
                })
        except Exception:
            pass

    return detected_items

def scan_image_bytes(image_bytes: bytes, filename: str = "image.png", source: str = "attachment") -> List[Dict[str, Any]]:
    """Decodes raw image bytes (PNG, JPG, WEBP, GIF, BMP) and scans for QR codes."""
    if not image_bytes:
        return []

    try:
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img_cv = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img_cv is None:
            # Fallback using PIL
            pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            img_cv = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

        qrs = detect_qr_in_cv2_image(img_cv)
        results = []
        for qr in qrs:
            results.append({
                "source": source,
                "filename": filename,
                "page": None,
                "decoded": qr["decoded"],
                "payload": qr["payload"],
                "payload_type": qr["payload_type"],
                "bounding_box": qr.get("bounding_box"),
                "ocr_text": "",
                "context_intents": []
            })
        return results
    except Exception as e:
        return []

def scan_pdf_bytes(pdf_bytes: bytes, filename: str = "document.pdf", max_pages: int = 10) -> List[Dict[str, Any]]:
    """
    Safely opens a PDF document in memory using PyMuPDF (fitz), renders each page to a high-res pixmap,
    scans for QR codes, extracts surrounding text on the page, and records page numbers.
    """
    if not pdf_bytes or fitz is None:
        return []

    results = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        pages_to_scan = min(len(doc), max_pages)

        for page_idx in range(pages_to_scan):
            page = doc[page_idx]
            page_num = page_idx + 1
            page_text = page.get_text("text") or ""
            intents = extract_ocr_context_intents(page_text)

            # Render page to pixmap (2x zoom for sharp QR code decoding)
            matrix = fitz.Matrix(2.0, 2.0)
            pix = page.get_pixmap(matrix=matrix, alpha=False)
            
            # Convert pixmap to numpy image
            img_np = np.frombuffer(pix.samples, dtype=np.uint8).reshape((pix.height, pix.width, pix.n))
            if pix.n == 4:
                img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGBA2BGR)
            elif pix.n == 3:
                img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
            else:
                img_cv = cv2.cvtColor(img_np, cv2.COLOR_GRAY2BGR)

            page_qrs = detect_qr_in_cv2_image(img_cv)

            for qr in page_qrs:
                results.append({
                    "source": "pdf_attachment",
                    "filename": filename,
                    "page": page_num,
                    "decoded": qr["decoded"],
                    "payload": qr["payload"],
                    "payload_type": qr["payload_type"],
                    "bounding_box": qr.get("bounding_box"),
                    "ocr_text": page_text.strip(),
                    "context_intents": intents
                })

        doc.close()
    except Exception:
        pass

    return results

def scan_base64_or_inline_image(data_uri: str, filename: str = "inline_image.png") -> List[Dict[str, Any]]:
    """Decodes data:image/...;base64,... URIs and scans for QR codes."""
    if not data_uri or "base64," not in data_uri:
        return []

    try:
        raw_b64 = data_uri.split("base64,")[1].strip()
        img_bytes = base64.b64decode(raw_b64)
        return scan_image_bytes(img_bytes, filename=filename, source="inline_image")
    except Exception:
        return []
