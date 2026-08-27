# Dataset Audit & Data Leakage Evaluation

## Executive Summary
All dataset files located in `dataset/` and training feature generation scripts in `training/` were audited to identify data contamination, class imbalance, duplicate entries, ground-truth label leakage, or target-correlated artifacts.

## 1. Dataset Breakdown & Metrics

| Dataset File | Total Samples | Legitimate (SAFE) | Phishing | Duplicates | Missing Values | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `phishing_emails.csv` | 150 | 75 | 75 | 0 | 0 | PASSED |
| `qr_phishing_dataset.csv` | 42 | 18 | 24 | 0 | 0 | PASSED |
| `regional_phishing_dataset.csv` | 520 | 250 | 270 | 0 | 0 | PASSED |
| `regional_train.csv` | 364 | 175 | 189 | 0 | 0 | PASSED |
| `regional_validation.csv` | 78 | 37 | 41 | 0 | 0 | PASSED |
| `regional_test.csv` | 78 | 38 | 40 | 0 | 0 | PASSED |
| `regional_adversarial_test.csv` | 24 | 10 | 14 | 0 | 0 | PASSED |

## 2. ML Data Leakage Audit
- **Verification Strategy**:
  - Inspected column schemas in `phishing_emails.csv`, `generated_xgb_features.csv`, and `training/build_xgb_dataset.py`.
  - Confirmed that features passed to models consist strictly of extracted raw text signals (`nlp_score`, `url_score`, `header_score`, `attachment_score`, `sender_behavior_score`).
  - Target labels (`label`), post-analysis verdicts, threat intelligence flags unavailable during inference, and dataset file metadata are **completely excluded** from model inputs.

## 3. Train / Validation / Test Separation
- Data splits for Indic/Regional MuRIL models follow strict 70% Train / 15% Validation / 15% Test proportions.
- An independent 24-sample adversarial test set (`regional_adversarial_test.csv`) was created to test robustness against transliterated, code-mixed, and subtle spear-phishing variants.
