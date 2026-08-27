# Real-Time Phishing & Social Engineering Detection System

Full-stack defensive prototype:

Email -> FastAPI -> Parser -> Header/Body/URL/Attachment/Behavior analysis
-> BERT/RoBERTa signal -> Threat Intelligence -> Feature Fusion -> XGBoost
-> Risk Score -> Explainability -> Action -> PostgreSQL -> React Dashboard

## Run backend
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload

Swagger: http://127.0.0.1:8000/docs

## Run frontend
cd frontend
npm install
npm run dev

## Training data
CSV columns:
text,label

label=0 legitimate
label=1 phishing

Example:
"Your account is suspended. Click here to verify.",1
"Team meeting is tomorrow at 10 AM.",0

Training:
python training/train_bert.py --csv dataset/phishing_emails.csv
python training/build_xgb_dataset.py --csv dataset/phishing_emails.csv
python training/train_xgboost.py --csv training/generated_xgb_features.csv

The API has a transparent fallback so the complete control flow can be demonstrated before trained models/API keys exist. It does not pretend that the fallback is a real trained BERT/XGBoost model.
