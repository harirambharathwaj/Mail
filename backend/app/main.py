from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db, save_analysis, get_recent, get_stats, get_recent_qr_scans
from .schemas import EmailRequest, AnalysisResponse
from .services.pipeline import analyze_email
from .services.qr_service import analyze_email_quishing, process_single_qr, analyze_qr_upload_file
from fastapi import UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Any

app = FastAPI(
    title="Phishing Detection API",
    version="1.0.0",
    description="Defensive phishing and social-engineering detection prototype."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

from .services.bert_model import get_bert
from .services.fusion import fusion_model

@app.get("/api/health")
def health():
    bert = get_bert(settings.bert_model_path)
    bert_loaded = bert.loaded if bert else False
    xgboost_loaded = fusion_model.model is not None
    return {
        "status": "ok",
        "bert_loaded": bert_loaded,
        "xgboost_loaded": xgboost_loaded,
        "fallback_mode": not (bert_loaded and xgboost_loaded)
    }

@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze(request: EmailRequest):
    result = analyze_email(request)
    row = save_analysis(request, result)
    result["id"] = row.id
    return result

class QRAnalyzeRequest(BaseModel):
    body: Optional[str] = ""
    attachments: Optional[List[Any]] = []
    inline_images: Optional[List[str]] = []
    raw_payload: Optional[str] = None

@app.post("/api/analyze/qr")
def analyze_qr(request: QRAnalyzeRequest):
    if request.raw_payload:
        item = process_single_qr({
            "source": "api_direct",
            "payload": request.raw_payload,
            "decoded": True,
            "filename": "direct_input"
        })
        from .services.qr_risk import calculate_overall_qr_risk
        return calculate_overall_qr_risk([item])
    
    return analyze_email_quishing(
        body=request.body or "",
        attachments=request.attachments or [],
        inline_images=request.inline_images or []
    )

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

@app.post("/api/qr/analyze")
async def analyze_uploaded_qr(file: UploadFile = File(...)):
    filename = file.filename or "uploaded_qr.png"
    ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Upload PNG, JPG, JPEG or WEBP."
        )

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail="File exceeds maximum allowed size (10 MB)."
        )

    return analyze_qr_upload_file(content, filename=filename)

@app.get("/api/qr/scans")
def get_qr_scans(limit: int = 50):
    return get_recent_qr_scans(limit)

class RegionalAnalyzeRequest(BaseModel):
    text: Optional[str] = ""
    subject: Optional[str] = ""
    body: Optional[str] = ""

@app.post("/api/analyze/regional")
def analyze_regional_endpoint(request: RegionalAnalyzeRequest):
    combined = request.text or f"{request.subject or ''}\n{request.body or ''}"
    from .services.language_id import detect_language
    from .services.muril_model import get_muril
    
    lang_info = detect_language(combined)
    muril = get_muril()
    muril_res = muril.predict(combined, lang_meta=lang_info)
    
    return {
        "text": combined[:200],
        "language_identification": lang_info,
        "regional_model": {
            "model_name": "google/muril-base-cased",
            "muril_probability": muril_res["muril_probability"],
            "confidence": muril_res["confidence"],
            "detected_intent": muril_res["detected_intent"],
            "evidence": muril_res["evidence"],
            "explanation": muril_res["explanation"]
        }
    }

@app.get("/api/alerts")
def alerts(limit: int = 20):
    return get_recent(limit)

@app.get("/api/metrics")
def metrics():
    return get_stats()

from .services.campaign.campaign_schema import CampaignAnalyzeRequest, CampaignAnalyzeResponse
from .services.campaign.campaign_service import analyze_campaigns

@app.post("/api/campaign/analyze", response_model=CampaignAnalyzeResponse)
def analyze_campaign_endpoint(request: CampaignAnalyzeRequest):
    return analyze_campaigns(request)

@app.get("/api/campaign/datasets")
def get_campaign_test_datasets():
    """Provides pre-validated authorized multi-channel campaign dataset scenarios for testing."""
    return [
        {
            "scenario_id": "SCENARIO_BANK_001",
            "name": "SBI / ICICI Banking Credential Harvest Campaign",
            "description": "Cross-channel campaign targeting banking users via Email, SMS shortlink, and WhatsApp QR lure.",
            "events": [
                {
                    "event_id": "EVT_EML_01",
                    "channel": "email",
                    "timestamp": "2026-08-28T10:01:00Z",
                    "sender": "security@sbxic-verify.com",
                    "subject": "Urgent SBI-ICICI Account Verification Required",
                    "body": "Dear Customer, unusual activity detected. Scan QR or verify at https://sbxic.com/verify-account",
                    "urls": ["https://sbxic.com/verify-account"],
                    "data_origin": "real"
                },
                {
                    "event_id": "EVT_SMS_02",
                    "channel": "sms",
                    "timestamp": "2026-08-28T10:08:00Z",
                    "sender": "+919876543210",
                    "body": "Urgent: SBI account blocked! Verify your KYC immediately at https://sbxic.com/verify-account",
                    "urls": ["https://sbxic.com/verify-account"],
                    "data_origin": "real"
                },
                {
                    "event_id": "EVT_WA_03",
                    "channel": "whatsapp",
                    "timestamp": "2026-08-28T10:19:00Z",
                    "sender": "Bank Support Team",
                    "body": "Aapka account block ho gaya hai. Fast KYC update: https://sbxic.com/verify-account",
                    "urls": ["https://sbxic.com/verify-account"],
                    "data_origin": "synthetic"
                }
            ]
        },
        {
            "scenario_id": "SCENARIO_BEC_002",
            "name": "Executive BEC & Wire Transfer Campaign",
            "description": "Targeted Spear-Phishing campaign impersonating CEO via HR Email and SMS urgency message.",
            "events": [
                {
                    "event_id": "EVT_EML_04",
                    "channel": "email",
                    "timestamp": "2026-08-28T14:00:00Z",
                    "sender": "ceo-update@mycompany-internal.com",
                    "subject": "Confidential Urgent Invoice Wire Transfer",
                    "body": "Payroll team, process this overdue invoice immediately: https://vendor-payroll-sync.com/invoice",
                    "urls": ["https://vendor-payroll-sync.com/invoice"],
                    "data_origin": "real"
                },
                {
                    "event_id": "EVT_SMS_05",
                    "channel": "sms",
                    "timestamp": "2026-08-28T14:12:00Z",
                    "sender": "+12025550198",
                    "body": "CEO Alert: I sent an urgent email. Process the invoice at https://vendor-payroll-sync.com/invoice now.",
                    "urls": ["https://vendor-payroll-sync.com/invoice"],
                    "data_origin": "synthetic"
                }
            ]
        }
    ]

