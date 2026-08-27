import joblib
import json
import pandas as pd
import numpy as np
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app.config import settings
from app.services.parser import parse_email
from app.services.analyzers import build_signals
from app.services.bert_model import get_bert

df = pd.read_csv("../dataset/phishing_emails.csv")
bert = get_bert(settings.bert_model_path)
xgb_model = joblib.load(settings.xgb_model_path)
scaler = joblib.load(settings.xgb_scaler_path)

print(f"XGBoost model classes: {xgb_model.classes_}")
print(f"Scaler mean: {scaler.mean_}")
print(f"Scaler scale: {scaler.scale_}")

for i in range(len(df)):
    row = df.iloc[i]
    sender_val = str(row.get("sender", ""))
    recipient_val = str(row.get("recipient", ""))
    subject_val = str(row.get("subject", ""))
    body_val = str(row.get("body", ""))
    
    headers_val = {}
    h_str = str(row.get("headers", "")).strip()
    if h_str.startswith("{"):
        try:
            headers_val = json.loads(h_str)
        except Exception:
            pass
            
    attachments_val = []
    a_str = str(row.get("attachments", "")).strip()
    if a_str.startswith("["):
        try:
            attachments_val = json.loads(a_str)
        except Exception:
            pass
            
    email = parse_email(sender_val, recipient_val, subject_val, body_val, headers_val, attachments_val)
    signals, reasons, urls = build_signals(email, settings.bert_model_path)
    
    vec = pd.DataFrame([[
        signals["nlp_score"],
        signals["url_score"],
        signals["header_score"],
        signals["attachment_score"],
        signals["sender_behavior_score"]
    ]], columns=["nlp_score", "url_score", "header_score", "attachment_score", "sender_behavior_score"])
    
    vec_s = scaler.transform(vec)
    probs = xgb_model.predict_proba(vec_s)[0]
    pred = xgb_model.predict(vec_s)[0]
    bert_p = bert.predict(f"{subject_val}\n{body_val}")
    
    print(f"[{i:02d}] True={row['label']} | BERT={bert_p:.3f} | XGB_prob={probs} (pred={pred}) | Signals: nlp={signals['nlp_score']:.2f}, url={signals['url_score']:.2f}, hdr={signals['header_score']:.2f}, att={signals['attachment_score']:.2f}, beh={signals['sender_behavior_score']:.2f} | Subj: {subject_val[:30]}")
