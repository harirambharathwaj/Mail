import io
import pytest
import qrcode
from PIL import Image
import fitz  # PyMuPDF

from app.services.qr_scanner import (
    scan_image_bytes,
    scan_pdf_bytes,
    determine_payload_type,
    extract_ocr_context_intents
)
from app.services.qr_service import analyze_email_quishing

def generate_qr_bytes(data: str, format: str = "PNG") -> bytes:
    """Helper to generate a real valid QR code image in memory."""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format=format)
    return buf.getvalue()

def generate_qr_pdf_bytes(qr_payload_page1: str, qr_payload_page2: str = None) -> bytes:
    """Helper to generate a real multi-page PDF document containing QR codes and text."""
    doc = fitz.open()

    # Page 1
    page1 = doc.new_page(width=600, height=800)
    page1.insert_text((50, 80), "Microsoft 365 Security Alert: Action Required immediately.", fontsize=14)
    page1.insert_text((50, 110), "Scan this QR code below to verify your account credentials:", fontsize=11)
    qr_bytes_1 = generate_qr_bytes(qr_payload_page1)
    rect1 = fitz.Rect(50, 140, 250, 340)
    page1.insert_image(rect1, stream=qr_bytes_1)

    # Page 2 (if specified)
    if qr_payload_page2:
        page2 = doc.new_page(width=600, height=800)
        page2.insert_text((50, 80), "Page 2: Second Multi-Factor Backup QR Code.", fontsize=14)
        qr_bytes_2 = generate_qr_bytes(qr_payload_page2)
        rect2 = fitz.Rect(50, 140, 250, 340)
        page2.insert_image(rect2, stream=qr_bytes_2)

    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()

def test_payload_classification():
    assert determine_payload_type("https://secure.login.microsoft.com/auth") == "https_url"
    assert determine_payload_type("http://insecure-portal.com/login") == "http_url"
    assert determine_payload_type("mailto:attacker@domain.com") == "mailto"
    assert determine_payload_type("tel:+1234567890") == "tel"
    assert determine_payload_type("WIFI:S:MyWifi;T:WPA;P:secret123;;") == "plain_text"

def test_qr_detection_png_and_jpg():
    # 1. Test PNG QR detection
    png_bytes = generate_qr_bytes("https://auth.company-login.xyz/verify", format="PNG")
    results = scan_image_bytes(png_bytes, filename="mfa_qr.png")
    assert len(results) >= 1
    assert results[0]["decoded"] is True
    assert results[0]["payload"] == "https://auth.company-login.xyz/verify"
    assert results[0]["payload_type"] == "https_url"

    # 2. Test JPEG QR detection
    jpg_bytes = generate_qr_bytes("https://payroll-update.net/login", format="JPEG")
    results_jpg = scan_image_bytes(jpg_bytes, filename="payroll.jpg")
    assert len(results_jpg) >= 1
    assert results_jpg[0]["payload"] == "https://payroll-update.net/login"

def test_qr_detection_in_pdf_page_extraction():
    # Generate 2-page PDF with QR on Page 1 and Page 2
    pdf_bytes = generate_qr_pdf_bytes(
        qr_payload_page1="https://microsoft-support-login.com/auth",
        qr_payload_page2="https://backup-portal.com/verify"
    )
    
    results = scan_pdf_bytes(pdf_bytes, filename="mfa_notice.pdf")
    assert len(results) == 2
    assert results[0]["page"] == 1
    assert "microsoft-support-login.com" in results[0]["payload"]
    assert "Microsoft 365" in results[0]["ocr_text"]
    assert "credential_verification" in results[0]["context_intents"]
    
    assert results[1]["page"] == 2
    assert "backup-portal.com" in results[1]["payload"]

def test_corrupted_or_non_qr_image():
    # Blank 100x100 white image
    img = Image.new("RGB", (100, 100), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    results = scan_image_bytes(buf.getvalue(), filename="blank.png")
    assert len(results) == 0

def test_full_quishing_analysis_service():
    pdf_bytes = generate_qr_pdf_bytes("http://microsoft-support-login.com/auth/verify?id=928")
    report = analyze_email_quishing(
        body="Urgent: Your account is scheduled for deactivation. Scan the QR code in the attached PDF.",
        attachments=[{"name": "Security_Update.pdf", "bytes": pdf_bytes}]
    )
    assert report["detected"] is True
    assert report["count"] == 1
    assert report["risk_level"] == "HIGH"
    assert report["risk_score"] >= 0.70
    assert any("page 1" in r for r in report["reasons"])
