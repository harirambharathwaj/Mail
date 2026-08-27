import argparse
import json
import sys
from pathlib import Path
import pandas as pd

# Add backend directory to python path
sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.parser import parse_email
from app.services.analyzers import build_signals

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True)
    p.add_argument("--output", default="generated_xgb_features.csv")
    p.add_argument("--bert-model", default=None, help="Path to fine-tuned BERT model")
    args = p.parse_args()

    df = pd.read_csv(args.csv)

    records = []
    for idx, row in df.iterrows():
        # Safeguard and deserialize JSON columns
        headers = row.get("headers", "{}")
        if pd.isna(headers) or not headers:
            headers = {}
        elif isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except Exception:
                headers = {}

        attachments = row.get("attachments", "[]")
        if pd.isna(attachments) or not attachments:
            attachments = []
        elif isinstance(attachments, str):
            try:
                attachments = json.loads(attachments)
            except Exception:
                attachments = []

        email = parse_email(
            sender=str(row.get("sender", "")),
            recipient=str(row.get("recipient", "")),
            subject=str(row.get("subject", "")),
            body=str(row.get("body", "")),
            headers=headers,
            attachments=attachments
        )

        # build_signals uses BERT if the model is fine-tuned (loaded from settings.bert_model_path or custom path).
        # We pass the custom fine-tuned model path to it.
        signals, reasons, urls = build_signals(email, args.bert_model)

        record = {
            "nlp_score": signals["nlp_score"],
            "url_score": signals["url_score"],
            "header_score": signals["header_score"],
            "attachment_score": signals["attachment_score"],
            "sender_behavior_score": signals["sender_behavior_score"],
            "label": "SAFE" if int(row["label"]) == 0 else "PHISHING"
        }
        records.append(record)

    out = pd.DataFrame(records)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.output, index=False)
    print(f"Wrote {len(out)} rows of features to {args.output}")

if __name__ == "__main__":
    main()
