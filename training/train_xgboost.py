import argparse
from pathlib import Path
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from xgboost import XGBClassifier

FEATURES = [
    "nlp_score",
    "url_score",
    "header_score",
    "attachment_score",
    "sender_behavior_score",
]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True)
    p.add_argument("--output", default="../artifacts/xgboost_phishing.joblib")
    p.add_argument("--scaler-output", default="../artifacts/xgb_scaler.joblib")
    args = p.parse_args()

    df = pd.read_csv(args.csv).dropna()
    X = df[FEATURES].astype(float)
    y = df["label"]

    classes = sorted(y.unique())
    if len(classes) < 2:
        raise ValueError("Need at least two classes.")

    label_to_id = {label: i for i, label in enumerate(classes)}
    y_encoded = y.map(label_to_id)

    scaler = StandardScaler()
    X_s = scaler.fit_transform(X)

    model = XGBClassifier(
        n_estimators=200,
        max_depth=3,
        learning_rate=0.1,
        subsample=1.0,
        colsample_bytree=1.0,
        min_child_weight=0.1,
        objective="multi:softprob" if len(classes) > 2 else "binary:logistic",
        eval_metric="mlogloss" if len(classes) > 2 else "logloss",
        random_state=42,
    )

    model.fit(X_s, y_encoded)
    pred = model.predict(X_s)

    print(classification_report(
        y_encoded,
        pred,
        target_names=[str(c) for c in classes],
        zero_division=0
    ))

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output)
    joblib.dump(scaler, args.scaler_output)
    print("Saved model:", args.output)
    print("Classes:", classes)

if __name__ == "__main__":
    main()
