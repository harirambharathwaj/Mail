from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db, save_analysis, get_recent, get_stats
from .schemas import EmailRequest, AnalysisResponse
from .services.pipeline import analyze_email

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

from .services.qr_service import analyze_email_quishing, process_single_qr
from pydantic import BaseModel
from typing import Optional, List, Any

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

@app.get("/api/alerts")
def alerts(limit: int = 50):
    return get_recent(limit)

@app.get("/api/stats")
def stats():
    return get_stats()
