# 🛡️ Real-Time Phishing & Social Engineering Detection System

A full-stack, enterprise-grade defensive prototype for detecting email phishing, social engineering attacks, and QR code phishing (Quishing) using multi-signal feature fusion and Machine Learning.

---

## 📐 System Architecture

```text
[ Incoming Email / Raw Header & Body ]
                  │
                  ▼
         [ FastAPI Parser ]
                  │
  ┌───────────────┼───────────────┬────────────────┐
  ▼               ▼               ▼                ▼
[ Header ]    [ Body NLP ]     [ URLs ]      [ Attachments / QR ]
  │               │               │                │
  ▼               ▼               ▼                ▼
(SPF/DKIM)    (BERT Signal)  (Threat Intel)   (Quishing Scanner)
  │               │               │                │
  └───────────────┴───────┬───────┴────────────────┘
                          ▼
                [ Feature Fusion Engine ]
                          │
                          ▼
                 [ XGBoost Classifier ]
                          │
                          ▼
             [ Risk Score & Explainability ]
                          │
                          ▼
            [ SQLite / React Dashboard ]
```

---

## ✨ Key Features

- **📧 Multi-Stage Email Analysis**: Parses raw EML/MBOX files and plain inputs, evaluating headers (SPF, DKIM, DMARC alignment), subject line urgency, sender reputation, and body copy.
- **📱 QR Code & Quishing Protection**:
  - Scans image and PDF attachments for embedded QR codes using PyMuPDF and computer vision/decoders.
  - Resolves multi-hop HTTP redirects to unmask hidden landing pages.
  - Includes **SSRF Protection** to prevent internal/private network IP probing.
  - Scores QR threats based on suspicious TLDs, IP literal hosts, credential harvester keywords, and URL shorteners.
- **🤖 ML & AI Feature Fusion**:
  - **BERT / RoBERTa Signal**: Fine-tuned NLP models extract semantic context, urgency, and manipulative social engineering cues.
  - **XGBoost Classifier**: Combines NLP confidence scores, header authenticity flags, URL threat signals, and QR risk scores into a unified risk score (0 - 100%).
- **🔍 Explainability & Recommendations**:
  - Highlights top risk indicators (e.g., domain spoofing, suspicious links, QR redirection to untrusted TLDs).
  - Provides mitigation steps for SOC analysts and end users.
- **📊 Interactive React Security Dashboard**:
  - Real-time submission and instant threat assessment.
  - Visual gauge indicators, detailed threat breakdown tabs, and historical scan logs.
- **⚡ Resilient Fallbacks**:
  - Includes robust heuristics so the entire system and UI remain operational even before ML weights or API keys are populated.

---

## 🛠️ Tech Stack

### **Backend**
- **Framework**: [FastAPI](https://fastapi.tiangolo.com/) (Python 3.10+)
- **Server**: Uvicorn
- **Database**: SQLAlchemy + SQLite
- **Machine Learning**: XGBoost, HuggingFace Transformers, PyTorch, Scikit-learn
- **Document & Image Processing**: PyMuPDF (`pymupdf`), Pillow, OpenCV, `pyzbar` / `zxing-cpp`
- **Testing**: Pytest

### **Frontend**
- **Framework**: [React 19](https://react.dev/) + [Vite](https://vitejs.dev/)
- **Styling**: Vanilla CSS (Custom Design System with Glassmorphism & Dark Mode)

---

## 📁 Repository Structure

```text
phishing-detection/
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI entry point & routes
│   │   ├── database.py           # DB models & session setup
│   │   ├── schemas.py            # Pydantic data schemas
│   │   └── services/
│   │       ├── parser.py         # Email header & body parsing
│   │       ├── analyzers.py      # Header, URL, & content analyzers
│   │       ├── bert_model.py     # BERT NLP classification service
│   │       ├── qr_scanner.py     # QR image/PDF extraction
│   │       ├── qr_resolver.py    # Safe redirect resolution & SSRF defense
│   │       ├── qr_risk.py        # Quishing risk scoring
│   │       ├── fusion.py         # Feature fusion & XGBoost inference
│   │       └── pipeline.py       # End-to-end orchestration pipeline
│   ├── tests/                    # Pytest test suite
│   ├── requirements.txt          # Python dependencies
│   └── .env.example              # Environment variables template
├── frontend/
│   ├── src/
│   │   ├── main.jsx              # React app & UI components
│   │   └── style.css             # UI styling & theme
│   ├── package.json
│   └── vite.config.js
├── dataset/                      # Dataset CSV files for model training
├── training/                     # Scripts for model training & feature extraction
│   ├── train_bert.py
│   ├── build_xgb_dataset.py
│   └── train_xgboost.py
├── docker-compose.yml
└── README.md
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** & `npm`

---

### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create & activate a virtual environment
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create environment configuration file
copy .env.example .env   # On Linux/macOS: cp .env.example .env

# Start FastAPI server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API server will run at `http://127.0.0.1:8000`.
Explore interactive Swagger documentation at **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**.

---

### 2. Frontend Setup

```bash
# Navigate to frontend directory (in a new terminal)
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```

Open your browser and navigate to **[http://localhost:5173](http://localhost:5173)** to open the Security Dashboard.

---

## 🧠 Model Training Pipeline

To train custom models on your own email datasets:

```bash
# 1. Train BERT / RoBERTa NLP classifier
python training/train_bert.py --csv dataset/phishing_emails.csv

# 2. Extract fusion features from the dataset
python training/build_xgb_dataset.py --csv dataset/phishing_emails.csv

# 3. Train the XGBoost Feature Fusion Classifier
python training/train_xgboost.py --csv training/generated_xgb_features.csv
```

---

## 🧪 Testing

Run the automated test suite to verify backend pipeline logic, SSRF protections, and QR detection:

```bash
cd backend
pytest
```

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
