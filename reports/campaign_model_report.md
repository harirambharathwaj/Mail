# Multi-Channel Phishing Campaign Correlation Model Report

## Executive Summary
The Aegis Campaign Correlation Engine identifies coordinated cross-channel phishing infrastructure across Email, SMS, and WhatsApp without relying on naive single-channel classification.

## Evaluation Metrics (Zero-Leakage Test Set)
* **Precision**: 100.0%
* **Recall**: 66.7%
* **F1-Score**: 80.0%
* **ROC-AUC**: 94.4%
* **PR-AUC**: 86.7%

## Signal Dimension Weights
1. **Infrastructure Match ($S_{\text{infra}}$)**: 0.60 (Domain eTLD+1, Redirect, QR, Attachment)
2. **Semantic / Intent Match ($S_{\text{content}}$)**: 0.20 (MuRIL multilingual embeddings & intent)
3. **Temporal Proximity ($S_{\text{temporal}}$)**: 0.15 (Decaying time window)
4. **Sender Identity ($S_{\text{sender}}$)**: 0.05 (Canonical E.164 phone & domain)
5. **Cross-Channel Progression ($S_{\text{channel}}$)**: +0.08 bonus for coordinated multi-channel blitz

## Anti-Overcorrelation Validation
* **Generic Urgency Test**: Passed (Generic phrases like "urgent verify account" score < 30)
* **Public Domain Test**: Passed (Shared public platforms like "google.com" or "bit.ly" alone score < 30)
* **Zero Template Leakage**: Passed (Grouped campaign-level splitting guaranteed)
