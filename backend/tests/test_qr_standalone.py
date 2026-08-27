import pytest
import io
import qrcode
from PIL import Image
from fastapi.testclient import TestClient

from app.main import app
from app.services.qr_scanner import scan_image_bytes
from app.services.qr_resolver import validate_url_for_ssrf, resolve_redirects
from app.services.qr_risk import evaluate_standalone_qr_risk

client = TestClient(app)

def create_test_qr_bytes(payload: str) -> bytes:
    """Helper to generate real QR code PNG image bytes for testing."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

# 1. Valid safe QR
def test_valid_safe_qr():
    img_bytes = create_test_qr_bytes("https://google.com")
    response = client.post(
        "/api/qr/analyze",
        files={"file": ("safe_qr.png", img_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["qr_detected"] is True
    assert data["risk_level"] in ("SAFE", "LOW RISK")
    assert data["risk_score"] < 0.60

# 2. Valid phishing QR
def test_valid_phishing_qr():
    img_bytes = create_test_qr_bytes("http://192.168.1.1/login-verify-account-mfa.xyz")
    response = client.post(
        "/api/qr/analyze",
        files={"file": ("phishing_qr.png", img_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["qr_detected"] is True
    assert data["risk_level"] in ("SUSPICIOUS", "PHISHING")
    assert data["risk_score"] >= 0.60

# 3. Invalid image format / bytes
def test_invalid_image_extension():
    response = client.post(
        "/api/qr/analyze",
        files={"file": ("malicious.exe", b"not an image file content", "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "Unsupported file type" in response.json()["detail"]

# 4. Image with no QR code
def test_image_with_no_qr():
    # Create plain white image without QR
    img = Image.new("RGB", (200, 200), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    response = client.post(
        "/api/qr/analyze",
        files={"file": ("no_qr.png", buf.getvalue(), "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is False
    assert data["qr_detected"] is False
    assert "No readable QR code was detected" in data["message"]

# 5. QR containing plain text
def test_qr_plain_text():
    img_bytes = create_test_qr_bytes("Hello World plain text snippet")
    response = client.post(
        "/api/qr/analyze",
        files={"file": ("text_qr.png", img_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["qr_detected"] is True
    assert data["payload_type"] == "plain_text"
    assert data["risk_level"] == "SAFE"

# 6. QR containing HTTP URL
def test_qr_http_url():
    img_bytes = create_test_qr_bytes("http://example-http-portal.com")
    response = client.post(
        "/api/qr/analyze",
        files={"file": ("http_qr.png", img_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["is_https"] is False

# 7. QR containing HTTPS URL
def test_qr_https_url():
    img_bytes = create_test_qr_bytes("https://secure.example.com")
    response = client.post(
        "/api/qr/analyze",
        files={"file": ("https_qr.png", img_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["is_https"] is True

# 8. Shortened URL
def test_shortened_url():
    img_bytes = create_test_qr_bytes("https://bit.ly/3xyzExample")
    response = client.post(
        "/api/qr/analyze",
        files={"file": ("short_qr.png", img_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert any("shortener" in r.lower() for r in data["reasons"])

# 9. Redirect URL & 10. Multiple redirects
def test_multiple_redirects():
    mock_item = {
        "payload": "http://short.url/link",
        "payload_type": "http_url",
        "original_url": "http://short.url/link",
        "final_url": "https://malicious-login-auth.com/verify",
        "redirect_chain": ["http://short.url/link", "https://redirect.com/hop", "https://malicious-login-auth.com/verify"],
        "redirect_count": 2,
        "resolution_success": True,
        "resolution_error": None
    }
    result = evaluate_standalone_qr_risk(mock_item, {})
    assert result["redirect_count"] == 2
    assert result["risk_level"] in ("SUSPICIOUS", "PHISHING")

# 11. Localhost URL & 12. Private IP URL (SSRF protections)
def test_ssrf_localhost_protection():
    is_safe, err = validate_url_for_ssrf("http://localhost:8000/admin")
    assert is_safe is False
    assert "Blocked internal or loopback" in err or "restricted" in err

def test_ssrf_private_ip_protection():
    is_safe, err = validate_url_for_ssrf("http://192.168.1.1/router-login")
    assert is_safe is False
    assert "restricted or private IP" in err

def test_ssrf_metadata_endpoint():
    is_safe, err = validate_url_for_ssrf("http://169.254.169.254/latest/meta-data/")
    assert is_safe is False

# 13. Malformed URL
def test_malformed_url():
    is_safe, err = validate_url_for_ssrf("http://[invalid-ipv6-address")
    assert is_safe is False

# 14. Threat intelligence API unconfigured behavior
def test_threat_intel_unconfigured():
    mock_item = {
        "payload": "https://example.org",
        "payload_type": "https_url",
        "original_url": "https://example.org",
        "final_url": "https://example.org",
        "redirect_chain": ["https://example.org"],
        "redirect_count": 0,
        "resolution_success": True
    }
    unintel = {
        "url": "https://example.org",
        "risk": 0.0,
        "virustotal": {"status": "unknown", "malicious": None},
        "safe_browsing": {"status": "unknown", "malicious": None}
    }
    result = evaluate_standalone_qr_risk(mock_item, unintel)
    assert result["threat_intelligence"]["virustotal"]["configured"] is False
    assert result["threat_intelligence"]["safe_browsing"]["configured"] is False

# 15. URL timeout / resolution error
def test_url_timeout_handling():
    res = resolve_redirects("https://10.255.255.1", timeout=0.5)
    assert res["resolution_success"] is False

# 16. Embedded text URL with banking brand typosquatting (e.g. hello this is url website is www.sbxic.com)
def test_embedded_url_typosquatting_qr():
    img_bytes = create_test_qr_bytes("hello this is url website is www.sbxic.com")
    response = client.post(
        "/api/qr/analyze",
        files={"file": ("embedded_qr.png", img_bytes, "image/png")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["qr_detected"] is True
    assert data["risk_level"] in ("SUSPICIOUS", "PHISHING")
    assert data["risk_score"] >= 0.60
    assert any("brand" in r.lower() or "typosquatting" in r.lower() or "lookalike" in r.lower() for r in data["reasons"])

