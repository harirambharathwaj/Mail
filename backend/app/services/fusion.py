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
        # Extract continuous signal values
        nlp = float(signals.get("nlp_score", 0.0))
        url = float(signals.get("url_score", 0.0))
        hdr = float(signals.get("header_score", 0.0))
        att = float(signals.get("attachment_score", 0.0))
        beh = float(signals.get("sender_behavior_score", 0.0))

        # Baseline multi-signal weighted summation
        weighted_base = (
            nlp * 0.35 +
            url * 0.25 +
            hdr * 0.15 +
            att * 0.15 +
            beh * 0.10
        )

        max_sig = max(nlp, url, hdr, att, beh)

        # Dynamic XGBoost inference if model and scaler are loaded
        xgb_phish_prob = None
        if self.model is not None and self.scaler is not None and np is not None:
            try:
                import pandas as pd
                df_feat = pd.DataFrame([[nlp, url, hdr, att, beh]], columns=FEATURE_NAMES)
                scaled_arr = self.scaler.transform(df_feat)
                model_probs = self.model.predict_proba(scaled_arr)[0]
                # Class 0 in xgboost_phishing.joblib represents PHISHING, Class 1 represents SAFE
                if len(model_probs) >= 2:
                    # Index 0 is PHISHING probability in the trained XGBoost model
                    if hasattr(self.model, "classes_") and list(self.model.classes_) == ["PHISHING", "SAFE"]:
                        xgb_phish_prob = float(model_probs[0])
                    elif hasattr(self.model, "classes_") and list(self.model.classes_) == [0, 1]:
                        xgb_phish_prob = float(model_probs[0])
                    else:
                        xgb_phish_prob = float(model_probs[0])
            except Exception:
                xgb_phish_prob = None

        if xgb_phish_prob is not None:
            weighted = weighted_base * 0.35 + xgb_phish_prob * 0.65
        else:
            # Smooth continuous blending proportional to signal weights and peak signal
            blend_factor = min(0.60, max_sig * 0.60)
            weighted = weighted_base * (1.0 - blend_factor) + (max_sig * 0.85) * blend_factor

        weighted = max(0.01, min(0.99, weighted))

        # Check for targeted spear-phishing (lookalikes or behavioral anomaly + content cues)
        is_spear = (
            (beh >= 0.70 and (nlp >= 0.20 or url >= 0.20 or hdr >= 0.35)) or
            (hdr >= 0.80 and (nlp >= 0.20 or url >= 0.20))
        )

        if is_spear:
            verdict = "SPEAR-PHISHING"
            risk_val = min(0.99, max(weighted, 0.82 + (hdr * 0.10) + (beh * 0.07)))
            confidence = min(0.99, max(0.82, 0.75 + (risk_val * 0.22)))
        elif weighted >= 0.40 or url >= 0.60 or att >= 0.75:
            verdict = "PHISHING"
            risk_val = min(0.98, max(0.50, weighted))
            confidence = min(0.98, max(0.72, 0.68 + (risk_val * 0.28)))
        elif weighted >= 0.15 or max_sig >= 0.25:
            verdict = "SUSPICIOUS"
            risk_val = min(0.49, max(0.15, weighted))
            confidence = min(0.85, max(0.60, 0.62 + (abs(risk_val - 0.30) * 0.5)))
        else:
            verdict = "SAFE"
            risk_val = max(0.01, min(0.14, weighted * 0.5))
            confidence = min(0.99, max(0.85, 0.99 - (risk_val * 1.5)))

        # Dynamic probability distribution
        p_phish = risk_val if verdict in ["PHISHING", "SPEAR-PHISHING"] else (0.2 * risk_val if verdict == "SUSPICIOUS" else 0.01)
        p_spear = risk_val if verdict == "SPEAR-PHISHING" else 0.0
        p_susp = risk_val if verdict == "SUSPICIOUS" else (0.15 * risk_val if verdict == "PHISHING" else 0.01)
        p_safe = max(0.0, 1.0 - (p_phish + p_spear + p_susp))
        tot = p_safe + p_susp + p_phish + p_spear

        probabilities = {
            "SAFE": round(p_safe / tot, 4),
            "SUSPICIOUS": round(p_susp / tot, 4),
            "PHISHING": round(p_phish / tot, 4),
            "SPEAR-PHISHING": round(p_spear / tot, 4),
        }

        return verdict, round(confidence, 4), probabilities, round(risk_val * 100, 1)

fusion_model = FusionModel()
