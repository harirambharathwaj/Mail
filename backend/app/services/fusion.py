from pathlib import Path
try:
    import numpy as np
except ImportError:
    np = None
try:
    import joblib
except ImportError:
    joblib = None
from ..config import settings

FEATURE_NAMES = [
    "nlp_score",
    "url_score",
    "header_score",
    "attachment_score",
    "sender_behavior_score",
]

class FusionModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        try:
            if joblib is not None and Path(settings.xgb_model_path).exists():
                self.model = joblib.load(settings.xgb_model_path)
            if joblib is not None and Path(settings.xgb_scaler_path).exists():
                self.scaler = joblib.load(settings.xgb_scaler_path)
        except Exception:
            self.model = None
            self.scaler = None

    def predict(self, signals):
        # Calculate integrated risk score
        weighted = (
            signals["nlp_score"] * 0.35 +
            signals["url_score"] * 0.30 +
            signals["header_score"] * 0.20 +
            signals["attachment_score"] * 0.15 +
            signals["sender_behavior_score"] * 0.15
        )
        
        # Boost risk if any single high-severity indicator exists
        max_signal = max(signals.values())
        if max_signal >= 0.80:
            weighted = max(weighted, 0.85)
        elif max_signal >= 0.50:
            weighted = max(weighted, 0.55)

        weighted = min(0.99, max(0.01, weighted))

        # Check for targeted spear-phishing
        is_spear = (
            (signals["sender_behavior_score"] >= 0.70 and (signals["nlp_score"] >= 0.30 or signals["url_score"] >= 0.30 or signals["header_score"] >= 0.40)) or
            (signals["header_score"] >= 0.80 and (signals["nlp_score"] >= 0.30 or signals["url_score"] >= 0.30))
        )

        if is_spear:
            verdict = "SPEAR-PHISHING"
            risk_val = max(weighted, 0.92)
            confidence = max(0.92, risk_val)
        elif weighted >= 0.55 or signals["url_score"] >= 0.75 or signals["attachment_score"] >= 0.75:
            verdict = "PHISHING"
            risk_val = weighted
            confidence = max(0.88, weighted)
        elif weighted >= 0.20 or max_signal >= 0.35:
            verdict = "SUSPICIOUS"
            risk_val = weighted
            confidence = 0.72 + (weighted * 0.20)
        else:
            verdict = "SAFE"
            risk_val = max(0.01, min(0.15, weighted * 0.4))
            confidence = 1.0 - risk_val

        probabilities = {
            "SAFE": round(1.0 - risk_val, 4),
            "SUSPICIOUS": round(risk_val if verdict == "SUSPICIOUS" else 0.0, 4),
            "PHISHING": round(risk_val if verdict in ["PHISHING", "SPEAR-PHISHING"] else 0.0, 4),
            "SPEAR-PHISHING": round(risk_val if verdict == "SPEAR-PHISHING" else 0.0, 4),
        }

        return verdict, round(confidence, 4), probabilities, round(risk_val * 100, 2)

fusion_model = FusionModel()
