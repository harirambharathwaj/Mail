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
EMBEDDED_URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"]+", re.I)
MAILTO_REGEX = re.compile(r"^mailto:([^?]+)", re.I)
TEL_REGEX = re.compile(r"^(?:tel:|telnet:|\+?\d{7,15}$)", re.I)

def extract_embedded_urls(text: str) -> List[str]:
    """Extracts all HTTP/HTTPS or www. URLs embedded anywhere within a text string."""
    if not text:
        return []
    matches = EMBEDDED_URL_REGEX.findall(text)
    cleaned = []
    for m in matches:
        url = m.rstrip(".,;:!?'\")}]")
        if url.lower().startswith("www."):
            url = "http://" + url
        cleaned.append(url)
    return list(dict.fromkeys(cleaned))

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
    elif EMBEDDED_URL_REGEX.search(text_clean):
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
    Scans a BGR/Grayscale OpenCV image array using a robust 6-pass multi-preprocessing pipeline:
      1. Original image multi-QR & single-QR detection
      2. CLAHE contrast-enhanced grayscale (low contrast QRs)
      3. Bitwise color inversion (dark mode / inverted QRs)
      4. Otsu binary thresholding (noisy / uneven lighting)
      5. Bicubic 2.5x upscaling (small / low-res QRs)
      6. Sharpening filter kernel (blurry QRs)
    """
    detected_items = []
    if image_bgr is None or image_bgr.size == 0:
        return detected_items

    detector = cv2.QRCodeDetector()
    found_payloads = set()

    def _try_decode(img_to_check):
        nonlocal detected_items, found_payloads
        if img_to_check is None:
            return
        # Multi-QR decode
        try:
            ok, decoded_info, points, _ = detector.detectAndDecodeMulti(img_to_check)
            if ok and decoded_info is not None:
                for idx, text in enumerate(decoded_info):
                    txt_str = str(text or "").strip()
                    if txt_str and txt_str not in found_payloads:
                        found_payloads.add(txt_str)
                        bbox = points[idx].tolist() if points is not None and len(points) > idx else None
                        detected_items.append({
                            "decoded": True,
                            "payload": txt_str,
                            "payload_type": determine_payload_type(txt_str),
                            "bounding_box": bbox
                        })
        except Exception:
            pass

        # Single-QR decode fallback
        if not detected_items or len(found_payloads) == 0:
            try:
                text, points, _ = detector.detectAndDecode(img_to_check)
                txt_str = str(text or "").strip()
                if txt_str and txt_str not in found_payloads:
                    found_payloads.add(txt_str)
                    bbox = points.tolist() if points is not None else None
                    detected_items.append({
                        "decoded": True,
                        "payload": txt_str,
                        "payload_type": determine_payload_type(txt_str),
                        "bounding_box": bbox
                    })
            except Exception:
                pass

    # Pass 1: Original BGR
    _try_decode(image_bgr)
    if detected_items:
        return detected_items

    # Convert to Grayscale
    if len(image_bgr.shape) == 3:
        gray = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2GRAY)
    else:
        gray = image_bgr.copy()

    # Pass 2: Contrast Stretching / CLAHE
    try:
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        _try_decode(enhanced)
        if detected_items:
            return detected_items
    except Exception:
        pass

    # Pass 3: Inverted Image (Dark-Mode QRs)
    try:
        inverted = cv2.bitwise_not(gray)
        _try_decode(inverted)
        if detected_items:
            return detected_items
    except Exception:
        pass

    # Pass 4: Otsu Binary Thresholding
    try:
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        _try_decode(thresh)
        if detected_items:
            return detected_items
    except Exception:
        pass

    # Pass 5: 2.5x Bicubic Upscaling (Small QRs)
    try:
        h, w = gray.shape[:2]
        if max(h, w) < 1500:
            upscaled = cv2.resize(gray, (0, 0), fx=2.5, fy=2.5, interpolation=cv2.INTER_CUBIC)
            _try_decode(upscaled)
            if detected_items:
                return detected_items
    except Exception:
        pass

    # Pass 6: Sharpening Kernel Filter (Blurry QRs)
    try:
        kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]], dtype=np.float32)
        sharpened = cv2.filter2D(gray, -1, kernel)
        _try_decode(sharpened)
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
    scans for QR codes, extracts raw embedded image streams, and records surrounding OCR text.
    """
    if not pdf_bytes or fitz is None:
        return []

    results = []
    seen_payloads = set()

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        pages_to_scan = min(len(doc), max_pages)

        for page_idx in range(pages_to_scan):
            page = doc[page_idx]
            page_num = page_idx + 1
            page_text = page.get_text("text") or ""
            intents = extract_ocr_context_intents(page_text)

            # 1. Render page to high-res pixmap (3x zoom)
            matrix = fitz.Matrix(3.0, 3.0)
            pix = page.get_pixmap(matrix=matrix, alpha=False)
            
            img_np = np.frombuffer(pix.samples, dtype=np.uint8).reshape((pix.height, pix.width, pix.n))
            if pix.n == 4:
                img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGBA2BGR)
            elif pix.n == 3:
                img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
            else:
                img_cv = cv2.cvtColor(img_np, cv2.COLOR_GRAY2BGR)

            page_qrs = detect_qr_in_cv2_image(img_cv)

            # 2. Extract raw embedded image streams directly from PDF page
            try:
                for img_info in page.get_images(full=True):
                    xref = img_info[0]
                    base_image = doc.extract_image(xref)
                    if base_image and "image" in base_image:
                        emb_bytes = base_image["image"]
                        emb_qrs = scan_image_bytes(emb_bytes, filename=f"{filename}_p{page_num}_img", source="pdf_attachment")
                        page_qrs.extend(emb_qrs)
            except Exception:
                pass

            for qr in page_qrs:
                p_text = str(qr.get("payload", "")).strip()
                if p_text and p_text not in seen_payloads:
                    seen_payloads.add(p_text)
                    results.append({
                        "source": "pdf_attachment",
                        "filename": filename,
                        "page": page_num,
                        "decoded": qr.get("decoded", True),
                        "payload": p_text,
                        "payload_type": qr.get("payload_type", determine_payload_type(p_text)),
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
