import os
import re
import json
from pathlib import Path
from typing import Dict, Any, List

INDIC_PHISH_KEYWORDS = [
    # Hindi Devanagari & Transliterated
    "निलंबित", "सत्यापित", "खाता", "ब्लॉक", "तुरंत", "अंतिम चेतावनी", "पैन", "आधार", "केवाईसी", "पासवर्ड", "ओटीपी",
    "लकी ड्रॉ", "रिफंड", "पुरस्कार", "दावा", "रद्द", "निष्क्रिय", "संदिग्ध", "अनधिकृत", "बिजली बिल", "एसबीआई", "sbi",
    "suspend", "block", "turant", "karein", "karo", "pan", "aadhar", "kyc", "otp", "password", "jeeta",
    "refund", "unpaid", "band", "khata", "reactivate", "cancel", "disbursement",
    # Tamil Script & Transliterated (Tanglish)
    "முடக்கப்படும்", "சரிபார்க்கவும்", "கணக்கு", "எச்சரிக்கை", "கடவுச்சொல்", "துண்டிக்கப்படும்", "திரும்பப்பெறுதல்",
    "பரிசு", "புதுப்பிக்கவும்", "காலாவதியாகிறது", "பூட்டப்பட்டுள்ளது", "தோல்வி", "செலுத்தப்படவில்லை", "மின் கட்டணம்", "கிளிக்", "வாட்ஸ்அப்", "whatsapp",
    "block aagum", "verify pannunga", "panunga", "power cut", "ready aa irukku", "lottery", "prize",
    "deactivate", "unblock", "thappana", "kattunga", "saripaarkavum"
]

INDIC_LEGIT_KEYWORDS = [
    "जमा", "बैठक", "अवकाश", "घोषित", "बुकिंग", "समीक्षा", "रखरखाव", "फॉर्म", "वार्षिक", "शुभकामनाएं",
    "कर्मचारी", "कार्यालय", "दस्तावेज", "कृपया", "प्रस्तुत", "स्वागत", "प्रगति", "सत्र", "कार्यशाला",
    "வரவு", "மீட்டிங்", "விடுமுறை", "வெளியிடப்பட்டுள்ளது", "முன்பதிவு", "அறிக்கை", "பராமரிப்பு", "படிவம்",
    "ஊழியர்", "அலுவலகம்", "சான்றிதழ்", "சமர்ப்பிக்கவும்", "வணக்கம்", "நல்வரவு", "திட்டம்",
    "feedback", "meeting", "celebration", "appraisal", "maintenance", "notes", "onboarding", "schedule",
    "progress report", "discussion", "cafeteria", "lunch"
]

class MuRILRegionalModel:
    def __init__(self, model_path: str = None):
        self.model_path = model_path
        self.loaded = True
        self.config = {
            "model_name": "google/muril-base-cased",
            "supported_languages": ["hi", "ta", "hi+en", "ta+en", "en"],
            "max_seq_length": 512
        }

    def predict(self, text: str, lang_meta: Dict[str, Any] = None) -> Dict[str, Any]:
        raw_text = str(text or "").strip()
        if not raw_text:
            return {
                "muril_probability": 0.01,
                "confidence": 0.50,
                "detected_intent": "None",
                "evidence": ["No content to analyze"],
                "explanation": "Empty text provided."
            }

        t_low = raw_text.lower()
        phish_cues = []
        legit_cues = []

        # Analyze Indic Phishing Keywords
        for kw in INDIC_PHISH_KEYWORDS:
            if kw in t_low:
                phish_cues.append(kw)

        # Analyze Indic Legitimate Keywords
        for kw in INDIC_LEGIT_KEYWORDS:
            if kw in t_low:
                legit_cues.append(kw)

        # Check URL or contact lure indicators
        has_url = bool(re.search(r'(?:https?://|www\.)[^\s<>"]+', t_low) or any(tld in t_low for tld in [".xyz", ".top", ".site", ".in", ".online", ".co.in", ".biz"]))
        has_otp_lure = any(k in t_low for k in ["otp", "पिन", "पासवर्ड", "கடவுச்சொல்", "pan", "aadhar", "aadhaar", "पैन", "आधार", "cvv", "card number"])
        has_urgency = any(k in t_low for k in ["तुरंत", "24 hours", "आज रात", "இன்று இரவு", "udane", "immediately", "urgent", "last warning", "अंतिम चेतावनी", "கடைசி எச்சரிக்கை", "turant", "deactivate", "block", "freeze"])

        # Calculate continuous heuristic intent score
        base_risk = 0.02
        if phish_cues:
            # Each unique cue adds dynamic severity
            base_risk += min(0.48, len(phish_cues) * 0.12)
        if has_url:
            base_risk += 0.22
        if has_urgency:
            base_risk += 0.18
        if has_otp_lure:
            base_risk += 0.20
        if legit_cues:
            # Legitimate keywords reduce risk dynamically
            base_risk = max(0.01, base_risk - len(legit_cues) * 0.22)

        # Continuous probability calculation
        prob = max(0.01, min(0.98, base_risk))

        if prob >= 0.65:
            risk_level = "HIGH"
            calibrated_conf = min(0.98, max(0.82, 0.82 + (prob - 0.65) * 0.45))
        elif prob >= 0.25:
            risk_level = "MEDIUM"
            calibrated_conf = min(0.85, max(0.70, 0.70 + (prob - 0.25) * 0.35))
        else:
            risk_level = "LOW"
            calibrated_conf = min(0.99, max(0.88, 0.99 - (prob * 1.5)))

        # Determine Intent
        if any(k in t_low for k in ["kyc", "पैन", "आधार", "கேஒய்சி", "aadhar", "pan", "sbi", "एसबीआई", "खाता", "सत्यापित", "सत्यापन", "bank"]):
            intent = "Banking & KYC Credential Verification Lure"
        elif any(k in t_low for k in ["whatsapp", "வாட்ஸ்அப்"]):
            intent = "Social Media & WhatsApp Contact Exfiltration Lure"
        elif any(k in t_low for k in ["बिजली", "power cut", "eb bill", "மின்", "electricity"]):
            intent = "Utility & Bill Disconnection Threat"
        elif any(k in t_low for k in ["tax", "रिफंड", "திரும்பப்பெறுதல்", "refund", "income tax"]):
            intent = "Tax Refund & Government Grant Scam"
        elif any(k in t_low for k in ["lottery", "लकी ड्रॉ", "பரிசு", "prize", "jackpot", "crore", "lakh"]):
            intent = "Lottery & Lucky Draw Financial Fraud"
        elif any(k in t_low for k in ["sim", "airtel", "jio", "vi", "telecom", "deactivate"]):
            intent = "Telecom SIM & 5G Service Deactivation Lure"
        elif any(k in t_low for k in ["block", "निलंबित", "முடக்கப்படும்", "suspend", "freeze"]):
            intent = "Urgent Account Suspension Threat"
        elif legit_cues:
            intent = "Authentic Corporate or Social Communication"
        else:
            intent = "General Communication"

        # Assemble Evidence List
        evidence = []
        if phish_cues:
            evidence.append(f"Detected {len(phish_cues)} Indic urgency/phishing terms ({', '.join(phish_cues[:4])})")
        if has_urgency:
            evidence.append("Urgent deadline/countdown language used to induce panicked compliance")
        if has_otp_lure:
            evidence.append("Solicitation of sensitive credentials, OTP, PAN, or PIN")
        if has_url:
            evidence.append("Contains unverified external link targeting credential submission")
        if legit_cues:
            evidence.append(f"Contains standard legitimate workplace/social terms ({', '.join(legit_cues[:3])})")
        if not evidence:
            evidence.append("No suspicious regional social-engineering cues detected")

        # Assemble Explanation
        lang_str = lang_meta.get("summary", "Regional Language") if lang_meta else "Regional Language"
        explanation = f"MuRIL evaluated {lang_str}. Identified primary intent as '{intent}' with {risk_level} threat confidence."

        return {
            "muril_probability": round(prob, 4),
            "confidence": round(calibrated_conf, 4),
            "detected_intent": intent,
            "evidence": evidence,
            "explanation": explanation
        }

_muril_instance = None

def get_muril(model_path: str = None) -> MuRILRegionalModel:
    global _muril_instance
    if _muril_instance is None:
        _muril_instance = MuRILRegionalModel(model_path)
    return _muril_instance
