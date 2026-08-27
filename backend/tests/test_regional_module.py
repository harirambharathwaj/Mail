import pytest
from app.services.language_id import detect_language
from app.services.muril_model import get_muril
from app.services.pipeline import analyze_email
from app.schemas import EmailRequest

def test_language_identification_devanagari():
    text = "प्रिय ग्राहक, आपका एसबीआई बैंक खाता आज रात 12 बजे तक निलंबित कर दिया जाएगा।"
    res = detect_language(text)
    assert res["language"] == "hi"
    assert res["script"] == "devanagari"
    assert res["code_mixed"] is False
    assert res["confidence"] >= 0.85

def test_language_identification_tamil():
    text = "அன்புள்ள வாடிக்கையாளரே, உங்கள் எஸ்பிஐ வங்கி கணக்கு இன்று இரவு முடக்கப்படும்."
    res = detect_language(text)
    assert res["language"] == "ta"
    assert res["script"] == "tamil"
    assert res["code_mixed"] is False
    assert res["confidence"] >= 0.85

def test_language_identification_hinglish():
    text = "Dear customer, aapka bank account block ho jayega within 24 hours. Please verify KYC immediately."
    res = detect_language(text)
    assert res["language"] == "hi+en"
    assert res["code_mixed"] is True
    assert res["transliterated"] is True
    assert "aapka" in res["detected_markers"] or "block" in res["detected_markers"] or "jayega" in res["detected_markers"]

def test_language_identification_tanglish():
    text = "Dear customer, ungal bank account block aagum within 24 hours. Verify pannunga."
    res = detect_language(text)
    assert res["language"] == "ta+en"
    assert res["code_mixed"] is True
    assert res["transliterated"] is True
    assert "ungal" in res["detected_markers"] or "pannunga" in res["detected_markers"]

def test_language_identification_english():
    text = "Hi team, please find the quarterly budget report attached for review."
    res = detect_language(text)
    assert res["language"] == "en"
    assert res["code_mixed"] is False
    assert res["transliterated"] is False

def test_language_identification_empty_or_unknown():
    res_empty = detect_language("")
    assert res_empty["language"] == "unknown"
    assert res_empty["confidence"] == 0.50

    res_symbols = detect_language("!!! @@@ ### $$$ %%%")
    assert res_symbols["language"] == "unknown"

def test_muril_hindi_phishing_detection():
    muril = get_muril()
    text = "प्रिय ग्राहक, आपका एसबीआई बैंक खाता आज रात निलंबित कर दिया जाएगा। तुरंत आधार और पैन सत्यापित करें: http://sbi-kyc.in"
    lang_info = detect_language(text)
    res = muril.predict(text, lang_meta=lang_info)
    assert res["muril_probability"] >= 0.70
    assert "Banking" in res["detected_intent"] or "Urgent" in res["detected_intent"]
    assert len(res["evidence"]) > 0

def test_muril_tamil_phishing_detection():
    muril = get_muril()
    text = "கடைசி எச்சரிக்கை: உங்கள் மின் கட்டணம் செலுத்தப்படவில்லை. இன்றே துண்டிக்கப்படும். செலுத்த கிளிக் செய்யவும்: http://tneb-bill.xyz"
    lang_info = detect_language(text)
    res = muril.predict(text, lang_meta=lang_info)
    assert res["muril_probability"] >= 0.70
    assert "Utility" in res["detected_intent"] or "Threat" in res["detected_intent"]

def test_muril_hard_negative_legitimate_hindi():
    muril = get_muril()
    text = "प्रिय कर्मचारी, कृपया अपने नए दस्तावेज सत्यापन के लिए मूल आधार कार्ड कार्यालय में प्रस्तुत करें।"
    lang_info = detect_language(text)
    res = muril.predict(text, lang_meta=lang_info)
    assert res["muril_probability"] <= 0.20

def test_muril_hard_negative_legitimate_tamil():
    muril = get_muril()
    text = "திட்ட மீட்டிங் நாளை பிற்பகல் 2 மணிக்கு நடைபெறும். அனைவரும் கலந்துகொள்ளவும்."
    lang_info = detect_language(text)
    res = muril.predict(text, lang_meta=lang_info)
    assert res["muril_probability"] <= 0.15

def test_end_to_end_hinglish_pipeline():
    req = EmailRequest(
        sender="security@hdfc-secure-auth.xyz",
        recipient="user@mycompany.com",
        subject="Aapka bank account block ho jayega",
        body="Dear customer, aapka bank account suspend ho jayega. Please click link to verify password immediately: http://hdfc-verify.top"
    )
    res = analyze_email(req)
    assert res["verdict"] in ["PHISHING", "SPEAR-PHISHING"]
    assert res["risk_score"] >= 60.0
    assert res["regional"]["language"] in ["hi+en", "hi"]
    assert res["regional"]["code_mixed"] is True
    assert res["regional"]["semantic_model_used"] == "MuRIL"

def test_end_to_end_tanglish_pipeline():
    req = EmailRequest(
        sender="alert@sbi-tamil-update.xyz",
        recipient="user@mycompany.com",
        subject="Ungal account block aagum",
        body="Dear customer, ungal bank account block aagum. Immediate aa link click panni verify pannunga: http://sbi-tamil.xyz"
    )
    res = analyze_email(req)
    assert res["verdict"] in ["PHISHING", "SPEAR-PHISHING"]
    assert res["risk_score"] >= 60.0
    assert res["regional"]["language"] in ["ta+en", "ta"]
    assert res["regional"]["code_mixed"] is True
    assert res["regional"]["semantic_model_used"] == "MuRIL"

def test_regression_english_email_uses_bert():
    req = EmailRequest(
        sender="hariram@mycompany.com",
        recipient="ceo@mycompany.com",
        subject="Quarterly Budget Review",
        body="Hi team, please find the quarterly budget report attached for your feedback."
    )
    res = analyze_email(req)
    assert res["verdict"] == "SAFE"
    assert res["risk_score"] <= 15.0
    assert res["regional"]["language"] == "en"
    assert res["regional"]["semantic_model_used"] == "English BERT"
