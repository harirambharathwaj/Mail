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
        if self.model is not None and np is not None:
            x = np.array([[signals[name] for name in FEATURE_NAMES]], dtype=float)
            x_for_model = self.scaler.transform(x) if self.scaler is not None else x
            proba = self.model.predict_proba(x_for_model)[0]
            classes = list(self.model.classes_)
            label_map = {0: "PHISHING", 1: "SAFE"}
            probabilities = {label_map.get(c, str(c)): float(p) for c, p in zip(classes, proba)}
            predicted_id = int(self.model.predict(x_for_model)[0])
            predicted = label_map.get(predicted_id, str(predicted_id))
            confidence = float(probabilities[predicted])
            return predicted, confidence, probabilities

        # Transparent demo fallback until a real XGBoost model is trained.
        weighted = (
            signals["nlp_score"] * 0.35 +
            signals["url_score"] * 0.30 +
            signals["header_score"] * 0.15 +
            signals["attachment_score"] * 0.10 +
            signals["sender_behavior_score"] * 0.10
        )

        if signals["sender_behavior_score"] >= 0.75 and (
            signals["nlp_score"] >= 0.60 or signals["url_score"] >= 0.45
        ):
            verdict = "SPEAR-PHISHING"
        elif weighted >= 0.55 or (
            signals["nlp_score"] >= 0.75 and signals["url_score"] >= 0.45
        ):
            verdict = "PHISHING"
        elif weighted >= 0.25 or max(signals.values()) >= 0.60:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return verdict, weighted, {
            "SAFE": max(0.0, 1 - weighted),
            "SUSPICIOUS": 0.0,
            "PHISHING": weighted,
            "SPEAR-PHISHING": 0.0,
        }

fusion_model = FusionModel()
