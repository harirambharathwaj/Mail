from pathlib import Path

class BertPhishingModel:
    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
        self.pipeline = None
        self.loaded = False
        try:
            from transformers import pipeline
            if self.model_path.exists():
                self.pipeline = pipeline(
                    "text-classification",
                    model=str(self.model_path),
                    tokenizer=str(self.model_path),
                    top_k=None
                )
                self.loaded = True
        except Exception:
            self.pipeline = None

    def predict(self, text: str) -> float:
        # Returns phishing probability in [0,1].
        # Expected fine-tuned labels: LABEL_0=legitimate, LABEL_1=phishing.
        if self.loaded:
            outputs = self.pipeline(text[:5000])
            if isinstance(outputs, list) and outputs and isinstance(outputs[0], list):
                outputs = outputs[0]
            scores = {x["label"].upper(): float(x["score"]) for x in outputs}
            if "LABEL_1" in scores:
                return scores["LABEL_1"]
            if "PHISHING" in scores:
                return scores["PHISHING"]
            return 0.0

        # Transparent demo fallback. This is NOT a trained BERT prediction.
        # Weight common phishing cues so the prototype remains useful before
        # trained artifacts are generated.
        t = text.lower()
        weighted_terms = {
            "urgent": 0.18,
            "action required": 0.16,
            "final warning": 0.22,
            "account suspended": 0.28,
            "unusual login": 0.18,
            "suspicious login": 0.20,
            "click here": 0.22,
            "verify": 0.14,
            "verify your account": 0.28,
            "verify your password": 0.30,
            "confirm your account": 0.28,
            "confirm your identity": 0.28,
            "password": 0.16,
            "otp": 0.20,
            "one time password": 0.22,
            "credential": 0.22,
            "credentials": 0.22,
            "login": 0.12,
            "within 10 minutes": 0.18,
            "immediately": 0.18,
            "avoid a payout delay": 0.20,
            "payment required": 0.22,
            "payment is required": 0.22,
            "wire transfer": 0.22,
            "bank account": 0.18,
            "bank account leak": 0.34,
            "account leak": 0.30,
            "account details": 0.22,
            "account detail": 0.22,
            "data leak": 0.28,
            "leaked": 0.24,
            "leak": 0.18,
            "bank acc": 0.24,
        }
        score = sum(weight for term, weight in weighted_terms.items() if term in t)

        if "http://" in t:
            score += 0.10
        if "https://" in t:
            score += 0.04

        return min(0.95, score)

bert_model = None

def get_bert(model_path):
    global bert_model
    if bert_model is None:
        bert_model = BertPhishingModel(model_path)
    return bert_model
