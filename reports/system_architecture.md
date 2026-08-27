# Real System Architecture Map

## Overview & End-to-End Data Pipeline Flow

```
[USER / FRONTEND REACT UI]
         │
         │ (HTTP POST /api/analyze, /api/analyze/qr, /api/qr/analyze, /api/analyze/regional)
         ▼
[FASTAPI REST API SERVER (`backend/app/main.py`)]
         │
         ├──► CORS & Input Validation (`schemas.py`)
         │
         ├──► Email Parsing & Normalization (`services/parser.py`)
         │
         ├──► Signal Extraction & Preprocessing (`services/analyzers.py`)
         │        ├─ Header & Sender Analysis (`analyze_headers`)
         │        ├─ Body Semantic Analysis (`analyze_body`)
         │        ├─ Attachment Risk Evaluation (`analyze_attachments`)
         │        ├─ Sender Behavior Profiling (`analyze_sender_behavior`)
         │        └─ URL Risk & Threat Intel (`threat_intel.py`)
         │
         ├──► Language Routing & Semantic Models (`language_id.py`)
         │        ├─ English (`en`) ──► English BERT (`bert_model.py` / `google-bert/bert-base-uncased`)
         │        └─ Indic/Regional ──► MuRIL Transformer (`muril_model.py` / `google/muril-base-cased`)
         │
         ├──► Quishing & QR Analysis Engine (`qr_service.py`)
         │        ├─ Image / PDF QR Decoder (`qr_scanner.py`)
         │        ├─ SSRF Protection & Redirect Resolver (`qr_resolver.py`)
         │        ├─ URL Threat Intelligence on Decoded URLs (`threat_intel.py`)
         │        └─ QR Risk Evaluator (`qr_risk.py`)
         │
         ├──► Machine Learning Fusion Layer (`services/fusion.py`)
         │        ├─ XGBoost Classifier (`models/xgboost_phishing.joblib` + scaler)
         │        └─ Decision Rule & Probability Normalizer
         │
         └──► Output Assembly & SQLite Database Storage (`database.py`)
                  │
                  ▼
[FRONTEND DASHBOARD VERDICT DISPLAY & METRIC SUMMARY]
```

## Component Telemetry

### 1. REST API & Endpoint Dispatcher (`backend/app/main.py`)
- **Input**: JSON payload (`EmailRequest`, `QRAnalyzeRequest`, `RegionalAnalyzeRequest`) or Multipart form data (`UploadFile`).
- **Output**: JSON `AnalysisResponse` containing verdict, risk score, confidence, signal breakdown, URLs, QR scan details, and regional metadata.
- **Dependencies**: `FastAPI`, `Pydantic`, `Uvicorn`, `CORSMiddleware`.
- **Failure Behavior**: Catches missing or malformed fields; returns HTTP 400 for invalid file uploads or oversize inputs.
- **Security Risks**: Unbounded payload processing or unvalidated file sizes (mitigated via 10MB limit in upload endpoint).

### 2. Signal Analyzer & Parser (`backend/app/services/analyzers.py`, `parser.py`)
- **Input**: Raw email fields (sender, recipient, subject, body, headers, attachments).
- **Output**: Signal dictionary with `nlp_score`, `url_score`, `header_score`, `attachment_score`, `sender_behavior_score`.
- **Dependencies**: Python standard library (`re`, `email.utils`, `urllib.parse`), `threat_intel.py`.
- **Failure Behavior**: Defaults missing fields to safe baseline values (0.0).
- **Security Risks**: Regex DoS on crafted header patterns or spoofed display names.

### 3. Semantic Language Models (`bert_model.py`, `muril_model.py`, `language_id.py`)
- **Input**: Text strings (subject + body).
- **Output**: Softmax probability float representing phishing intent.
- **Dependencies**: PyTorch / HuggingFace `transformers` if available; fallback heuristic rules if PyTorch is absent.
- **Failure Behavior**: Gracefully falls back to pattern-based keyword heuristics if model files are missing or unreadable.
- **Security Risks**: Truncation of long emails (>512 tokens); handling of code-mixed or adversarial input.

### 4. Quishing & SSRF Protection Engine (`qr_scanner.py`, `qr_resolver.py`, `qr_risk.py`)
- **Input**: Image bytes, PDF bytes, or raw URL payloads.
- **Output**: QR detection status, redirect chain telemetry, destination URL threat score, and overall QR risk.
- **Dependencies**: `pyzbar`, `opencv-python`, `PyMuPDF` (fitz), `requests`, `ipaddress`, `socket`.
- **Failure Behavior**: Returns `qr_detected: False` or `resolution_error` string if network resolution fails or image is unreadable.
- **Security Risks**: SSRF targeting internal services (`127.0.0.1`, `169.254.169.254`, private subnet IP ranges) via URL redirects in QR payload.

### 5. Threat Intelligence (`threat_intel.py`)
- **Input**: Extracted URL string.
- **Output**: Dict with heuristic risk score, VirusTotal query result, and Safe Browsing query result.
- **Dependencies**: `requests`, environment variables `VT_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`.
- **Failure Behavior**: If API keys are missing or network request fails, returns `"status": "unknown"` or `"status": "unavailable"` without failing the request or falsely zeroing the overall threat score.
- **Security Risks**: API key leakage or external API rate limiting.

### 6. Fusion & Decision Engine (`fusion.py`)
- **Input**: Dictionary of signals (`nlp_score`, `url_score`, `header_score`, `attachment_score`, `sender_behavior_score`).
- **Output**: Tuple (`verdict`, `confidence`, `probabilities`, `risk_score`).
- **Dependencies**: `joblib`, `scikit-learn`, `xgboost`, `numpy`, `pandas`.
- **Failure Behavior**: If XGBoost model file is missing or unreadable, computes weighted baseline signal score.
- **Security Risks**: Inconsistent probability calibration or unvalidated score addition.
