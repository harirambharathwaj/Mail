import pytest
from app.config import settings
from app.services.bert_model import get_bert
from app.services.fusion import fusion_model
from app.services.pipeline import analyze_email
from app.schemas import EmailRequest

def test_bert_model_regression_and_weights_intact():
    """Verify BERT model loads and provides predictions without modification."""
    bert = get_bert(settings.bert_model_path)
    assert bert is not None
    assert bert.loaded is True

    # Test that model executes and returns valid probability scores
    res = bert.predict("Hi Alice, let's sync up for the project kickoff meeting tomorrow at 2 PM.")
    assert isinstance(res, float)
    assert 0.0 <= res <= 1.0

    # Test high phishing intent text
    phish_score = bert.predict("URGENT: Your account has been compromised. Verify your password immediately or your access will be suspended.")
    assert phish_score >= 0.70

def test_xgboost_fusion_model_regression():
    """Verify XGBoost fusion model computes baseline verdicts accurately without modification."""
    # 1. Clean signals -> SAFE verdict
    clean_signals = {
        "nlp_score": 0.02,
        "url_score": 0.0,
        "header_score": 0.0,
        "attachment_score": 0.0,
        "sender_behavior_score": 0.0
    }
    verdict, confidence, probs, risk_score = fusion_model.predict(clean_signals)
    assert verdict == "SAFE"
    assert risk_score < 20.0
    assert confidence > 0.85

    # 2. Malicious signals -> PHISHING verdict
    phish_signals = {
        "nlp_score": 0.95,
        "url_score": 0.90,
        "header_score": 0.85,
        "attachment_score": 0.0,
        "sender_behavior_score": 0.0
    }
    verdict_phish, conf_phish, _, risk_phish = fusion_model.predict(phish_signals)
    assert verdict_phish in ("PHISHING", "SPEAR-PHISHING")
    assert risk_phish >= 75.0

def test_pipeline_normal_email_without_qr():
    """Verify standard email detection operates with quishing detected=False."""
    req = EmailRequest(
        sender="colleague@mycompany.com",
        recipient="you@mycompany.com",
        subject="Project status sync",
        body="Hey, let's review the sprint deliverables this afternoon. Thanks!"
    )
    result = analyze_email(req)
    assert result["quishing"]["detected"] is False
    assert "verdict" in result
    assert "risk_score" in result

def test_pipeline_quishing_email_elevation():
    """Verify quishing email elevates risk and verdict to PHISHING with explainability."""
    from tests.test_qr_detection import generate_qr_pdf_bytes
    pdf_bytes = generate_qr_pdf_bytes("http://microsoft-support-login.com/auth/verify")

    req = EmailRequest(
        sender="security@external-domain.com",
        recipient="user@mycompany.com",
        subject="Account Security Alert: Scan Required",
        body="Scan the attached QR code to verify your single sign-on credentials immediately.",
        attachments=[{"name": "mfa_reset.pdf", "bytes": pdf_bytes}]
    )
    result = analyze_email(req)
    assert result["verdict"] in ("PHISHING", "SPEAR-PHISHING")
    assert result["quishing"]["detected"] is True
    assert result["quishing"]["risk_level"] == "HIGH"
    assert result["risk_score"] >= 70.0
    assert any("QR code" in r for r in result["reasons"])
    assert "QUARANTINE" in result["actions"]
