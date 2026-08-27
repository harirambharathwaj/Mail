import os
import sys
import json
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve,
    accuracy_score
)

# Add backend directory to sys.path to import existing services
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app.config import settings
from app.services.parser import parse_email
from app.services.analyzers import build_signals
from app.services.bert_model import get_bert

def compute_metrics(y_true, y_prob, threshold=0.5):
    y_pred = (np.array(y_prob) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    
    try:
        auc = roc_auc_score(y_true, y_prob)
    except Exception:
        auc = 0.5
        
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(auc), 4),
        "fpr": round(float(fpr), 4),
        "fnr": round(float(fnr), 4),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn)
    }

def main():
    base_dir = Path(__file__).resolve().parent.parent
    dataset_path = base_dir / "dataset" / "phishing_emails.csv"
    reports_dir = base_dir / "reports"
    cm_dir = reports_dir / "confusion_matrices"
    roc_dir = reports_dir / "roc_curves"
    
    reports_dir.mkdir(parents=True, exist_ok=True)
    cm_dir.mkdir(parents=True, exist_ok=True)
    roc_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    print(f"Loaded {len(df)} samples ({df['label'].sum()} phishing, {len(df) - df['label'].sum()} safe)")
    
    # 1. Load untouched models
    bert = get_bert(settings.bert_model_path)
    xgb_model = joblib.load(settings.xgb_model_path)
    xgb_scaler = joblib.load(settings.xgb_scaler_path)
    
    print(f"Loaded BERT model (loaded={bert.loaded})")
    print(f"Loaded XGBoost model ({type(xgb_model).__name__})")
    
    # 2. Extract model probabilities for all dataset items
    records = []
    for idx, row in df.iterrows():
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
                
        email = parse_email(
            sender=sender_val,
            recipient=recipient_val,
            subject=subject_val,
            body=body_val,
            headers=headers_val,
            attachments=attachments_val
        )
        
        signals, reasons, urls = build_signals(email, settings.bert_model_path)
        
        # BERT probability
        combined_text = f"{subject_val}\n{body_val}"
        bert_prob = float(bert.predict(combined_text))
        
        # XGBoost probability of Phishing (Class 0 in trained artifact = PHISHING)
        X_vec = np.array([[
            signals["nlp_score"],
            signals["url_score"],
            signals["header_score"],
            signals["attachment_score"],
            signals["sender_behavior_score"]
        ]])
        X_s = xgb_scaler.transform(X_vec)
        probs_all = xgb_model.predict_proba(X_s)[0]
        xgb_prob = float(probs_all[0])
        
        records.append({
            "email_id": idx,
            "sender": sender_val,
            "recipient": recipient_val,
            "subject": subject_val,
            "body": body_val,
            "label": int(row["label"]),
            "bert_probability": round(bert_prob, 4),
            "xgb_probability": round(xgb_prob, 4),
            "nlp_score": signals["nlp_score"],
            "url_score": signals["url_score"],
            "header_score": signals["header_score"],
            "attachment_score": signals["attachment_score"],
            "sender_behavior_score": signals["sender_behavior_score"]
        })
        
    full_df = pd.DataFrame(records)
    
    # 3. Stratified Split into Validation (50%) and Test (50%)
    indices = np.arange(len(full_df))
    y = full_df["label"].values
    
    val_idx, test_idx = train_test_split(
        indices,
        test_size=0.5,
        stratify=y,
        random_state=42
    )
    
    val_df = full_df.iloc[val_idx].copy().reset_index(drop=True)
    test_df = full_df.iloc[test_idx].copy().reset_index(drop=True)
    
    print(f"\nDataset Partitioning:")
    print(f"  Validation Set: {len(val_df)} samples ({val_df['label'].sum()} phishing, {len(val_df) - val_df['label'].sum()} safe)")
    print(f"  Test Set:       {len(test_df)} samples ({test_df['label'].sum()} phishing, {len(test_df) - test_df['label'].sum()} safe)")
    
    # 4. Tune alpha on VALIDATION ONLY
    print("\n--- Tuning Fusion Alpha on Validation Set Only ---")
    alpha_candidates = np.linspace(0.0, 1.0, 21)
    val_results = []
    
    for alpha in alpha_candidates:
        val_fusion_probs = alpha * val_df["bert_probability"] + (1.0 - alpha) * val_df["xgb_probability"]
        m = compute_metrics(val_df["label"], val_fusion_probs)
        val_results.append({
            "alpha": round(float(alpha), 2),
            **m
        })
        
    val_res_df = pd.DataFrame(val_results)
    
    # Selection criteria on validation: highest F1-score, then highest ROC-AUC
    best_val_row = val_res_df.sort_values(by=["f1_score", "roc_auc", "recall"], ascending=[False, False, False]).iloc[0]
    best_alpha = float(best_val_row["alpha"])
    print(f"Validation Tuning Complete.")
    print(f"  Best Validation Alpha: {best_alpha:.2f} (Val F1: {best_val_row['f1_score']:.4f}, Val AUC: {best_val_row['roc_auc']:.4f}, Val Recall: {best_val_row['recall']:.4f})")
    
    # 5. Evaluate Systems on Held-out TEST Set
    print(f"\n--- Evaluating Systems on Fixed TEST Set (Identical Dataset) ---")
    
    # Compute probabilities for Test Set
    test_df["bert_prob"] = test_df["bert_probability"]
    test_df["xgb_prob"] = test_df["xgb_probability"]
    test_df["fusion_prob"] = best_alpha * test_df["bert_prob"] + (1.0 - best_alpha) * test_df["xgb_prob"]
    
    test_bert_metrics = compute_metrics(test_df["label"], test_df["bert_prob"])
    test_xgb_metrics = compute_metrics(test_df["label"], test_df["xgb_prob"])
    test_fusion_metrics = compute_metrics(test_df["label"], test_df["fusion_prob"])
    
    # Also compute on Full Dataset for overall benchmarking
    full_df["fusion_probability"] = best_alpha * full_df["bert_probability"] + (1.0 - best_alpha) * full_df["xgb_probability"]
    full_bert_metrics = compute_metrics(full_df["label"], full_df["bert_probability"])
    full_xgb_metrics = compute_metrics(full_df["label"], full_df["xgb_probability"])
    full_fusion_metrics = compute_metrics(full_df["label"], full_df["fusion_probability"])
    
    # 6. Build Comparison Table
    comparison_records = [
        {
            "System": "SYSTEM A: BERT Only",
            "Scope": "Test Set (N=17)",
            "Alpha": 1.0,
            "Accuracy": test_bert_metrics["accuracy"],
            "Precision": test_bert_metrics["precision"],
            "Recall": test_bert_metrics["recall"],
            "F1_Score": test_bert_metrics["f1_score"],
            "ROC_AUC": test_bert_metrics["roc_auc"],
            "FPR": test_bert_metrics["fpr"],
            "FNR": test_bert_metrics["fnr"],
            "TP": test_bert_metrics["tp"],
            "FP": test_bert_metrics["fp"],
            "TN": test_bert_metrics["tn"],
            "FN": test_bert_metrics["fn"]
        },
        {
            "System": "SYSTEM B: XGBoost Only",
            "Scope": "Test Set (N=17)",
            "Alpha": 0.0,
            "Accuracy": test_xgb_metrics["accuracy"],
            "Precision": test_xgb_metrics["precision"],
            "Recall": test_xgb_metrics["recall"],
            "F1_Score": test_xgb_metrics["f1_score"],
            "ROC_AUC": test_xgb_metrics["roc_auc"],
            "FPR": test_xgb_metrics["fpr"],
            "FNR": test_xgb_metrics["fnr"],
            "TP": test_xgb_metrics["tp"],
            "FP": test_xgb_metrics["fp"],
            "TN": test_xgb_metrics["tn"],
            "FN": test_xgb_metrics["fn"]
        },
        {
            "System": f"SYSTEM C: BERT + XGBoost Fusion (Alpha={best_alpha:.2f})",
            "Scope": "Test Set (N=17)",
            "Alpha": best_alpha,
            "Accuracy": test_fusion_metrics["accuracy"],
            "Precision": test_fusion_metrics["precision"],
            "Recall": test_fusion_metrics["recall"],
            "F1_Score": test_fusion_metrics["f1_score"],
            "ROC_AUC": test_fusion_metrics["roc_auc"],
            "FPR": test_fusion_metrics["fpr"],
            "FNR": test_fusion_metrics["fnr"],
            "TP": test_fusion_metrics["tp"],
            "FP": test_fusion_metrics["fp"],
            "TN": test_fusion_metrics["tn"],
            "FN": test_fusion_metrics["fn"]
        },
        {
            "System": "SYSTEM A: BERT Only",
            "Scope": "Full Dataset (N=34)",
            "Alpha": 1.0,
            "Accuracy": full_bert_metrics["accuracy"],
            "Precision": full_bert_metrics["precision"],
            "Recall": full_bert_metrics["recall"],
            "F1_Score": full_bert_metrics["f1_score"],
            "ROC_AUC": full_bert_metrics["roc_auc"],
            "FPR": full_bert_metrics["fpr"],
            "FNR": full_bert_metrics["fnr"],
            "TP": full_bert_metrics["tp"],
            "FP": full_bert_metrics["fp"],
            "TN": full_bert_metrics["tn"],
            "FN": full_bert_metrics["fn"]
        },
        {
            "System": "SYSTEM B: XGBoost Only",
            "Scope": "Full Dataset (N=34)",
            "Alpha": 0.0,
            "Accuracy": full_xgb_metrics["accuracy"],
            "Precision": full_xgb_metrics["precision"],
            "Recall": full_xgb_metrics["recall"],
            "F1_Score": full_xgb_metrics["f1_score"],
            "ROC_AUC": full_xgb_metrics["roc_auc"],
            "FPR": full_xgb_metrics["fpr"],
            "FNR": full_xgb_metrics["fnr"],
            "TP": full_xgb_metrics["tp"],
            "FP": full_xgb_metrics["fp"],
            "TN": full_xgb_metrics["tn"],
            "FN": full_xgb_metrics["fn"]
        },
        {
            "System": f"SYSTEM C: BERT + XGBoost Fusion (Alpha={best_alpha:.2f})",
            "Scope": "Full Dataset (N=34)",
            "Alpha": best_alpha,
            "Accuracy": full_fusion_metrics["accuracy"],
            "Precision": full_fusion_metrics["precision"],
            "Recall": full_fusion_metrics["recall"],
            "F1_Score": full_fusion_metrics["f1_score"],
            "ROC_AUC": full_fusion_metrics["roc_auc"],
            "FPR": full_fusion_metrics["fpr"],
            "FNR": full_fusion_metrics["fnr"],
            "TP": full_fusion_metrics["tp"],
            "FP": full_fusion_metrics["fp"],
            "TN": full_fusion_metrics["tn"],
            "FN": full_fusion_metrics["fn"]
        }
    ]
    
    comp_df = pd.DataFrame(comparison_records)
    comp_csv_path = reports_dir / "model_comparison.csv"
    comp_json_path = reports_dir / "model_comparison.json"
    
    comp_df.to_csv(comp_csv_path, index=False)
    
    comp_json_data = {
        "experiment_summary": {
            "dataset_total": len(full_df),
            "phishing_count": int(full_df["label"].sum()),
            "safe_count": int(len(full_df) - full_df["label"].sum()),
            "val_size": len(val_df),
            "test_size": len(test_df),
            "best_validation_alpha": best_alpha,
            "alpha_search_space": [round(float(a), 2) for a in alpha_candidates]
        },
        "validation_tuning_results": val_results,
        "test_evaluation_results": {
            "bert_only": test_bert_metrics,
            "xgboost_only": test_xgb_metrics,
            "fusion": test_fusion_metrics
        },
        "full_dataset_results": {
            "bert_only": full_bert_metrics,
            "xgboost_only": full_xgb_metrics,
            "fusion": full_fusion_metrics
        }
    }
    
    with open(comp_json_path, "w", encoding="utf-8") as f:
        json.dump(comp_json_data, f, indent=2)
        
    print(f"Saved: {comp_csv_path}")
    print(f"Saved: {comp_json_path}")
    
    # 7. Comprehensive Error Analysis
    print("\n--- Performing Error Analysis & Category Breakdown ---")
    error_records = []
    
    for idx, row in full_df.iterrows():
        y_true = int(row["label"])
        bert_p = float(row["bert_probability"])
        xgb_p = float(row["xgb_probability"])
        fus_p = float(row["fusion_probability"])
        
        bert_pred = int(bert_p >= 0.5)
        xgb_pred = int(xgb_p >= 0.5)
        fus_pred = int(fus_p >= 0.5)
        
        category = "OTHER"
        explanation = ""
        
        if y_true == 1:
            if bert_pred == 1 and xgb_pred == 0:
                category = "CATEGORY_A (BERT Catches, XGBoost Misses)"
                explanation = (
                    "Social engineering or linguistic urgency successfully identified by BERT's semantic attention, "
                    "while technical structured indicators (URL/domain/attachment) were absent or bypassed XGBoost."
                )
            elif xgb_pred == 1 and bert_pred == 0:
                category = "CATEGORY_B (XGBoost Catches, BERT Misses)"
                explanation = (
                    "Technical indicators (malicious attachment extension, lookalike domain, reply-to trap, or header anomaly) "
                    "flagged by XGBoost, while body text appeared polite, conversational, or lacked explicit urgency keywords."
                )
            elif bert_pred == 0 and xgb_pred == 0:
                category = "CATEGORY_C (Both Miss)"
                explanation = (
                    "Sophisticated attack where text used subtle conversational tone with zero keywords AND "
                    "technical headers/domains mimicked legitimate infrastructure without triggering static rules."
                )
            elif bert_pred == 1 and xgb_pred == 1:
                category = "CATEGORY_D (Both Catch)"
                explanation = (
                    "Multi-signal threat containing both strong semantic urgency/credential theft cues "
                    "and identifiable technical indicators (lookalike URLs, brand spoofing, or abnormal headers)."
                )
        else:
            if fus_pred == 0 and bert_pred == 0 and xgb_pred == 0:
                category = "TRUE_NEGATIVE (Both Correctly Safe)"
                explanation = "Legitimate business/personal email with verified headers and normal conversational syntax."
            elif bert_pred == 1 or xgb_pred == 1:
                category = "FALSE_POSITIVE (False Alarm)"
                explanation = (
                    f"Safe email incorrectly flagged by {'BERT (NLP semantic false positive)' if bert_pred else 'XGBoost (technical indicator false positive)'}."
                )
                
        error_records.append({
            "email_id": idx,
            "sender": row["sender"],
            "subject": row["subject"],
            "true_label": y_true,
            "bert_prob": bert_p,
            "bert_pred": bert_pred,
            "xgb_prob": xgb_p,
            "xgb_pred": xgb_pred,
            "fusion_prob": round(fus_p, 4),
            "fusion_pred": fus_pred,
            "nlp_score": row["nlp_score"],
            "url_score": row["url_score"],
            "header_score": row["header_score"],
            "attachment_score": row["attachment_score"],
            "sender_behavior_score": row["sender_behavior_score"],
            "category": category,
            "expert_explanation": explanation
        })
        
    error_df = pd.DataFrame(error_records)
    error_csv_path = reports_dir / "error_analysis.csv"
    error_df.to_csv(error_csv_path, index=False)
    print(f"Saved: {error_csv_path}")
    
    # 8. Confusion Matrices & ROC Curves Data Export
    cm_summary = {
        "test_set": {
            "bert_only": {
                "tp": test_bert_metrics["tp"],
                "fp": test_bert_metrics["fp"],
                "tn": test_bert_metrics["tn"],
                "fn": test_bert_metrics["fn"],
                "matrix": [[test_bert_metrics["tn"], test_bert_metrics["fp"]], [test_bert_metrics["fn"], test_bert_metrics["tp"]]]
            },
            "xgboost_only": {
                "tp": test_xgb_metrics["tp"],
                "fp": test_xgb_metrics["fp"],
                "tn": test_xgb_metrics["tn"],
                "fn": test_xgb_metrics["fn"],
                "matrix": [[test_xgb_metrics["tn"], test_xgb_metrics["fp"]], [test_xgb_metrics["fn"], test_xgb_metrics["tp"]]]
            },
            "fusion": {
                "tp": test_fusion_metrics["tp"],
                "fp": test_fusion_metrics["fp"],
                "tn": test_fusion_metrics["tn"],
                "fn": test_fusion_metrics["fn"],
                "matrix": [[test_fusion_metrics["tn"], test_fusion_metrics["fp"]], [test_fusion_metrics["fn"], test_fusion_metrics["tp"]]]
            }
        },
        "full_dataset": {
            "bert_only": {
                "tp": full_bert_metrics["tp"],
                "fp": full_bert_metrics["fp"],
                "tn": full_bert_metrics["tn"],
                "fn": full_bert_metrics["fn"],
                "matrix": [[full_bert_metrics["tn"], full_bert_metrics["fp"]], [full_bert_metrics["fn"], full_bert_metrics["tp"]]]
            },
            "xgboost_only": {
                "tp": full_xgb_metrics["tp"],
                "fp": full_xgb_metrics["fp"],
                "tn": full_xgb_metrics["tn"],
                "fn": full_xgb_metrics["fn"],
                "matrix": [[full_xgb_metrics["tn"], full_xgb_metrics["fp"]], [full_xgb_metrics["fn"], full_xgb_metrics["tp"]]]
            },
            "fusion": {
                "tp": full_fusion_metrics["tp"],
                "fp": full_fusion_metrics["fp"],
                "tn": full_fusion_metrics["tn"],
                "fn": full_fusion_metrics["fn"],
                "matrix": [[full_fusion_metrics["tn"], full_fusion_metrics["fp"]], [full_fusion_metrics["fn"], full_fusion_metrics["tp"]]]
            }
        }
    }
    
    # Export CSV summary for confusion matrices
    cm_rows = [
        {"system": "BERT Only", "scope": "Test Set", **cm_summary["test_set"]["bert_only"]},
        {"system": "XGBoost Only", "scope": "Test Set", **cm_summary["test_set"]["xgboost_only"]},
        {"system": f"Fusion (Alpha={best_alpha:.2f})", "scope": "Test Set", **cm_summary["test_set"]["fusion"]},
        {"system": "BERT Only", "scope": "Full Dataset", **cm_summary["full_dataset"]["bert_only"]},
        {"system": "XGBoost Only", "scope": "Full Dataset", **cm_summary["full_dataset"]["xgboost_only"]},
        {"system": f"Fusion (Alpha={best_alpha:.2f})", "scope": "Full Dataset", **cm_summary["full_dataset"]["fusion"]}
    ]
    pd.DataFrame(cm_rows).to_csv(cm_dir / "confusion_matrices.csv", index=False)

    with open(cm_dir / "confusion_matrices.json", "w", encoding="utf-8") as f:
        json.dump(cm_summary, f, indent=2)
        
    # Generate ROC Curve Coordinates
    fpr_bert, tpr_bert, thresh_bert = roc_curve(full_df["label"], full_df["bert_probability"])
    fpr_xgb, tpr_xgb, thresh_xgb = roc_curve(full_df["label"], full_df["xgb_probability"])
    fpr_fus, tpr_fus, thresh_fus = roc_curve(full_df["label"], full_df["fusion_probability"])
    
    # Save ROC curves table CSV
    roc_rows = []
    for model_name, fprs, tprs, threshs in [
        ("BERT Only", fpr_bert, tpr_bert, thresh_bert),
        ("XGBoost Only", fpr_xgb, tpr_xgb, thresh_xgb),
        (f"Fusion (Alpha={best_alpha:.2f})", fpr_fus, tpr_fus, thresh_fus)
    ]:
        for f_val, t_val, th_val in zip(fprs, tprs, threshs):
            roc_rows.append({
                "model": model_name,
                "fpr": round(float(f_val), 4),
                "tpr": round(float(t_val), 4),
                "threshold": round(float(th_val), 4)
            })
    pd.DataFrame(roc_rows).to_csv(roc_dir / "roc_curves_data.csv", index=False)
    
    roc_data = {
        "bert_only": {
            "auc": full_bert_metrics["roc_auc"],
            "fpr": [round(float(x), 4) for x in fpr_bert],
            "tpr": [round(float(x), 4) for x in tpr_bert],
            "thresholds": [round(float(x), 4) for x in thresh_bert]
        },
        "xgboost_only": {
            "auc": full_xgb_metrics["roc_auc"],
            "fpr": [round(float(x), 4) for x in fpr_xgb],
            "tpr": [round(float(x), 4) for x in tpr_xgb],
            "thresholds": [round(float(x), 4) for x in thresh_xgb]
        },
        "fusion": {
            "auc": full_fusion_metrics["roc_auc"],
            "alpha": best_alpha,
            "fpr": [round(float(x), 4) for x in fpr_fus],
            "tpr": [round(float(x), 4) for x in tpr_fus],
            "thresholds": [round(float(x), 4) for x in thresh_fus]
        }
    }
    
    with open(roc_dir / "roc_curves_data.json", "w", encoding="utf-8") as f:
        json.dump(roc_data, f, indent=2)
        
    # Plot high-res charts if matplotlib is available
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        
        # 1. Confusion Matrices Plot
        fig, axes = plt.subplots(1, 3, figsize=(16, 5))
        sns.set_theme(style="darkgrid")
        
        cms = [
            ("BERT Only (NLP)", full_bert_metrics),
            ("XGBoost Only (Tabular)", full_xgb_metrics),
            (f"Fusion (Alpha={best_alpha:.2f})", full_fusion_metrics)
        ]
        
        for i, (title, m) in enumerate(cms):
            matrix = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
            sns.heatmap(
                matrix,
                annot=True,
                fmt="d",
                cmap="Blues" if i < 2 else "Greens",
                cbar=False,
                ax=axes[i],
                xticklabels=["Pred Safe (0)", "Pred Phish (1)"],
                yticklabels=["True Safe (0)", "True Phish (1)"],
                annot_kws={"size": 14, "weight": "bold"}
            )
            axes[i].set_title(f"{title}\nF1: {m['f1_score']:.3f} | AUC: {m['roc_auc']:.3f}", fontsize=12, fontweight="bold")
            axes[i].set_xlabel("Predicted Label")
            axes[i].set_ylabel("True Label")
            
        plt.tight_layout()
        plt.savefig(cm_dir / "confusion_matrices_comparison.png", dpi=300)
        plt.close()
        print(f"Saved: {cm_dir / 'confusion_matrices_comparison.png'}")
        
        # 2. ROC Curves Plot
        plt.figure(figsize=(8, 6))
        plt.plot(fpr_bert, tpr_bert, label=f"BERT Only (AUC = {full_bert_metrics['roc_auc']:.3f})", color="#3b82f6", linewidth=2.5)
        plt.plot(fpr_xgb, tpr_xgb, label=f"XGBoost Only (AUC = {full_xgb_metrics['roc_auc']:.3f})", color="#f59e0b", linewidth=2.5)
        plt.plot(fpr_fus, tpr_fus, label=f"Fusion Alpha={best_alpha:.2f} (AUC = {full_fusion_metrics['roc_auc']:.3f})", color="#10b981", linewidth=3.0)
        plt.plot([0, 1], [0, 1], "k--", alpha=0.5, label="Random Guess (AUC = 0.500)")
        plt.xlabel("False Positive Rate (FPR)", fontsize=11, fontweight="bold")
        plt.ylabel("True Positive Rate (Recall / TPR)", fontsize=11, fontweight="bold")
        plt.title("ROC Curves Comparison: BERT vs XGBoost vs Multi-Modal Fusion", fontsize=13, fontweight="bold")
        plt.legend(loc="lower right", fontsize=10)
        plt.grid(True, linestyle="--", alpha=0.6)
        plt.tight_layout()
        plt.savefig(roc_dir / "roc_comparison.png", dpi=300)
        plt.close()
        print(f"Saved: {roc_dir / 'roc_comparison.png'}")
        
    except Exception as e:
        print(f"Note: Matplotlib plotting encountered: {e}")
        
    print("\n================ EVALUATION SUMMARY ================")
    print(comp_df.to_string())
    print("====================================================\n")

if __name__ == "__main__":
    main()
