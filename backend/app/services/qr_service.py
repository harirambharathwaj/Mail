import base64
from typing import List, Dict, Any, Optional
from .qr_scanner import scan_image_bytes, scan_pdf_bytes, scan_base64_or_inline_image, determine_payload_type, extract_embedded_urls
from .qr_resolver import resolve_redirects
from .threat_intel import analyze_url
from .qr_risk import evaluate_qr_item_risk, calculate_overall_qr_risk

def process_single_qr(raw_qr_item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Takes a raw decoded QR item, resolves redirects via SSRF-safe resolver,
    invokes existing URL threat intelligence on the final destination,
    and evaluates QR item risk.
    """
    payload = raw_qr_item.get("payload", "")
    payload_type = raw_qr_item.get("payload_type", determine_payload_type(payload))
    
    embedded_urls = extract_embedded_urls(payload)
    
    original_url = payload if payload_type in ("http_url", "https_url", "url") and payload.lower().startswith(("http://", "https://", "www.")) else (embedded_urls[0] if embedded_urls else None)
    if embedded_urls and not original_url:
        original_url = embedded_urls[0]
        payload_type = "url"

    final_url = original_url
    redirect_chain = [original_url] if original_url else []
    redirect_count = 0
    resolution_success = True
    resolution_error = None
    url_intel = {}

    # If payload is a URL or contains an embedded URL, resolve redirects safely
    if original_url:
        resolution = resolve_redirects(original_url)
        final_url = resolution.get("final_url", original_url)
        redirect_chain = resolution.get("redirect_chain", [original_url])
        redirect_count = resolution.get("redirect_count", 0)
        resolution_success = resolution.get("resolution_success", True)
        resolution_error = resolution.get("resolution_error")

        # Invoke existing URL Threat Intelligence on final URL
        url_intel = analyze_url(final_url)
        
        # If final URL domain is safe/shortener but payload text contains another embedded URL (e.g. www.sbxic.com), analyze embedded target
        if embedded_urls:
            for emb_u in embedded_urls:
                emb_intel = analyze_url(emb_u)
                if float(emb_intel.get("risk", 0.0)) > float(url_intel.get("risk", 0.0)):
                    url_intel = emb_intel
                    final_url = emb_u

    item_record = {
        "source": raw_qr_item.get("source", "attachment"),
        "filename": raw_qr_item.get("filename", ""),
        "page": raw_qr_item.get("page"),
        "decoded": raw_qr_item.get("decoded", True),
        "payload": payload,
        "payload_type": payload_type,
        "original_url": original_url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "redirect_count": redirect_count,
        "resolution_success": resolution_success,
        "resolution_error": resolution_error,
        "bounding_box": raw_qr_item.get("bounding_box"),
        "ocr_text": raw_qr_item.get("ocr_text", ""),
        "context_intents": raw_qr_item.get("context_intents", []),
        "url_threat_intel": url_intel,
    }

    # Evaluate risk for this specific QR item
    item_risk, item_reasons = evaluate_qr_item_risk(item_record, url_intel)
    item_record["item_risk"] = item_risk
    item_record["reasons"] = item_reasons

    return item_record

def analyze_email_quishing(
    body: str,
    attachments: List[Any],
    inline_images: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Comprehensive QR Phishing analysis across email text, inline images, and attachments (PDF, PNG, JPG, WEBP).
    """
    detected_raw_qrs: List[Dict[str, Any]] = []

    # 1. Check inline images (base64 data URIs)
    if inline_images:
        for idx, img_uri in enumerate(inline_images):
            if isinstance(img_uri, str):
                qrs = scan_base64_or_inline_image(img_uri, filename=f"inline_{idx+1}.png")
                detected_raw_qrs.extend(qrs)

    # 2. Check attachments
    for att in (attachments or []):
        att_name = "attachment"
        att_bytes = None
        att_content_b64 = None

        if isinstance(att, dict):
            att_name = str(att.get("name", att.get("filename", "attachment"))).strip()
            if "bytes" in att and isinstance(att["bytes"], (bytes, bytearray)):
                att_bytes = bytes(att["bytes"])
            elif "content" in att and isinstance(att["content"], str):
                att_content_b64 = att["content"]
            elif "base64" in att and isinstance(att["base64"], str):
                att_content_b64 = att["base64"]
        elif isinstance(att, str):
            att_name = att.strip()

        # If base64 content is provided
        if att_content_b64 and not att_bytes:
            try:
                # Remove header if present
                if "base64," in att_content_b64:
                    att_content_b64 = att_content_b64.split("base64,")[1]
                att_bytes = base64.b64decode(att_content_b64)
            except Exception:
                att_bytes = None

        att_name_lower = att_name.lower()

        # Scan PDF attachments
        if att_name_lower.endswith(".pdf") and att_bytes:
            pdf_qrs = scan_pdf_bytes(att_bytes, filename=att_name)
            detected_raw_qrs.extend(pdf_qrs)

        # Scan Image attachments
        elif any(att_name_lower.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"]) and att_bytes:
            img_qrs = scan_image_bytes(att_bytes, filename=att_name)
            detected_raw_qrs.extend(img_qrs)

        # Check if attachment contains explicit simulated_qr object (from demo UI templates)
        elif isinstance(att, dict) and att.get("simulated_qr"):
            sim = att["simulated_qr"]
            detected_raw_qrs.append({
                "source": "pdf_attachment" if att_name_lower.endswith(".pdf") else "attachment",
                "filename": att_name,
                "page": sim.get("page", 1 if att_name_lower.endswith(".pdf") else None),
                "decoded": True,
                "payload": sim.get("payload", "https://mycompany.com/internal/portal"),
                "payload_type": determine_payload_type(sim.get("payload", "")),
                "bounding_box": [[100, 100], [300, 100], [300, 300], [100, 300]],
                "ocr_text": sim.get("ocr_text", "Scan QR code to access corporate service."),
                "context_intents": sim.get("context_intents", [])
            })

    # Process all detected QR items through SSRF-safe resolver & threat intel
    processed_items = [process_single_qr(qr) for qr in detected_raw_qrs]

    # Calculate overall QR risk report
    return calculate_overall_qr_risk(processed_items)

def analyze_qr_upload_file(file_bytes: bytes, filename: str = "uploaded_qr.png") -> Dict[str, Any]:
    """
    Decodes an uploaded QR image file, resolves redirects safely, runs URL threat analysis,
    and returns a complete standalone QR phishing verdict.
    """
    from .qr_risk import evaluate_standalone_qr_risk
    from ..database import save_qr_scan

    if not file_bytes:
        res = {
            "success": False,
            "qr_detected": False,
            "message": "Uploaded file is empty."
        }
        return res

    # 1. Scan image bytes for QR codes
    filename_lower = filename.lower()
    if filename_lower.endswith(".pdf"):
        raw_qrs = scan_pdf_bytes(file_bytes, filename=filename)
    else:
        raw_qrs = scan_image_bytes(file_bytes, filename=filename, source="upload")

    if not raw_qrs:
        res = {
            "success": False,
            "qr_detected": False,
            "filename": filename,
            "message": "No readable QR code was detected in the uploaded image."
        }
        # Save unreadable scan record
        try:
            save_qr_scan(res)
        except Exception:
            pass
        return res

    # 2. Take the primary detected QR code
    primary_qr = raw_qrs[0]

    # 3. Process single QR item (resolves redirects with SSRF check, threat intel)
    item_record = process_single_qr(primary_qr)

    # 4. Compute standalone risk verdict and breakdown
    result = evaluate_standalone_qr_risk(item_record, item_record.get("url_threat_intel") or {})
    result["filename"] = filename

    # 5. Persist scan in DB history
    try:
        save_qr_scan(result)
    except Exception as e:
        print(f"Warning: Failed to save QR scan to database: {e}")

    return result

