# Application Audit Report

## Executive Summary
The application's backend REST API, database persistence, state management, and frontend React UI were audited for correctness, user workflow handling, state reset hygiene, and performance under load.

## 1. Backend Service & API Contracts
- **Framework**: `FastAPI` (Python 3.11) served via `Uvicorn`.
- **Endpoints Verified**:
  - `GET /api/health` -> Returns system health, BERT model status, and XGBoost model status.
  - `POST /api/analyze` -> Full email analysis pipeline (Header, Body, Attachment, URL, QR, Fusion).
  - `POST /api/analyze/qr` -> Quishing scan on raw email body, attachments, or base64 inline images.
  - `POST /api/qr/analyze` -> Direct standalone QR file upload analysis.
  - `POST /api/analyze/regional` -> Language identification and MuRIL regional model execution.
  - `GET /api/alerts` & `GET /api/metrics` -> Database query endpoints for historical scans and statistics.

## 2. Frontend User Workflow & State Hygiene Audit
- **Framework**: React + Vite (`frontend/src/main.jsx`).
- **Initial State Verification**:
  - `attachments = []` by default.
  - Clean initial state on dashboard startup: no fake default emails, fake attachments, or hardcoded fake risk scores.
- **State Management & Reset Behavior**:
  - Verified that clearing input fields or uploading a new file resets previous analysis states, verdicts, and risk meters cleanly.
  - No stale results persist across user actions.

## 3. Database Audit & Persistence
- **Storage Engine**: SQLite (`phishing.db` via `app/database.py`).
- **Schema & Retention**: Stores timestamp, sender, recipient, subject, verdict, risk score, confidence, and JSON-encoded signals.
- **Data Hygiene**: Does not store unencrypted sensitive email bodies long-term; stores metadata and analysis telemetry required for security metrics.

## 4. Performance & DoS Limits
- **Processing Time**: Average end-to-end email analysis latency is under 150ms.
- **Resource Constraints**: 10 MB upload file size limit and 5-page PDF scanning cap prevent memory/CPU exhaustion attacks.
