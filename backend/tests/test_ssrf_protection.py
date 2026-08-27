import pytest
from app.services.qr_resolver import (
    validate_url_for_ssrf,
    is_safe_ip,
    resolve_redirects
)

def test_private_ip_detection():
    assert is_safe_ip("127.0.0.1") is False
    assert is_safe_ip("10.0.0.1") is False
    assert is_safe_ip("172.16.0.5") is False
    assert is_safe_ip("192.168.1.1") is False
    assert is_safe_ip("169.254.169.254") is False  # Cloud metadata
    assert is_safe_ip("8.8.8.8") is True          # Google Public DNS
    assert is_safe_ip("1.1.1.1") is True          # Cloudflare DNS

def test_ssrf_url_validation():
    # 1. Block localhost / 127.0.0.1
    is_safe, err = validate_url_for_ssrf("http://127.0.0.1:8000/secret")
    assert is_safe is False
    assert "restricted or private" in err.lower() or "blocked" in err.lower()

    # 2. Block localhost hostname
    is_safe, err = validate_url_for_ssrf("http://localhost:5000/api")
    assert is_safe is False

    # 3. Block Cloud metadata endpoint
    is_safe, err = validate_url_for_ssrf("http://169.254.169.254/latest/meta-data")
    assert is_safe is False

    # 4. Block non-http schemes (file://, gopher://, dict://)
    is_safe, err = validate_url_for_ssrf("file:///etc/passwd")
    assert is_safe is False
    assert "scheme" in err.lower()

    # 5. Allow legitimate public domain
    is_safe, err = validate_url_for_ssrf("https://www.google.com/search")
    assert is_safe is True
    assert err is None

def test_resolve_redirects_ssrf_protection():
    # Attempting to resolve a private IP must be blocked immediately
    res = resolve_redirects("http://192.168.1.100/admin")
    assert res["resolution_success"] is False
    assert "SSRF" in res["resolution_error"]
